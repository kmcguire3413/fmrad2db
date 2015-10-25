use std::sync::mpsc::{Sender, Receiver, channel};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

use super::NetOp;
use super::packets::EthIp4TcpPacket;

pub enum TcpChannelState {
    Connecting,
    Connected,
    Disconnected,
}

pub struct TcpSocketHeldPacket {
    seq:                            u32,
    buf:                            Vec<u8>,
}

pub struct TcpSocketSystem {
    txstate:                TcpChannelState,
    rxstate:                TcpChannelState,
    dst_port:                    u16,
    src_port:                    u16,
    dst_ip:                 u32,
    src_ip:                 u32,
    src_mac:                Vec<u8>,
    dst_mac:                Vec<u8>,
    ack:                    u32,
    seq:                    u32,
    mtu:                           usize,
    handle:                        usize,
    holding:                Vec<TcpSocketHeldPacket>,
    tx:                            Sender<TcpSocketMessage>,
    rx:                            Receiver<TcpSocketMessage>,
    net_tx:                 Sender<NetOp>,
    def_gw_mac6:            Vec<u8>,
}

pub enum TcpSocketMessage {
    Data(Vec<u8>),
    Connect { dstip: u32, dstport: u16 },
    Disconnect,

    Disconnected,
    Connected,
    EndOfStream,
}

pub struct TcpSocket {
    handle:                       usize,
   connected:              bool,
    pub tx:                       Sender<TcpSocketMessage>,
    pub rx:                       Receiver<TcpSocketMessage>,
    net_tx:                 Sender<NetOp>,
}

pub enum TcpSocketReadError {
    EndOfStream,
    Disconnected,
    Unknown,
   NoData,
}

impl TcpSocket {
    pub fn new(net_tx: Sender<NetOp>) -> TcpSocket {
        let (tx_tx, tx_rx): (Sender<TcpSocketMessage>, Receiver<TcpSocketMessage>) = channel();
        let (rx_tx, rx_rx): (Sender<TcpSocketMessage>, Receiver<TcpSocketMessage>) = channel();

        static next_handle: AtomicUsize = ATOMIC_USIZE_INIT;

        let new_handle = next_handle.fetch_add(1, Ordering::Relaxed);

        let sysmsg = NetOp::Ip4TcpSocketRegister {
            tx:       tx_rx,
            rx:       rx_tx,
            handle:   new_handle,
        };

        /*
            Let the system create the protected component of this socket.
        */
        net_tx.send(sysmsg);

        TcpSocket {
            tx:         tx_tx,
            rx:         rx_rx,
            handle:     new_handle,
            net_tx:     net_tx,
            connected:  false,
        }
    }

    pub fn new_adv(net_tx: Sender<NetOp>, port: u16, mtu: usize) -> TcpSocket {
        let (tx_tx, tx_rx): (Sender<TcpSocketMessage>, Receiver<TcpSocketMessage>) = channel();
        let (rx_tx, rx_rx): (Sender<TcpSocketMessage>, Receiver<TcpSocketMessage>) = channel();

        static next_handle: AtomicUsize = ATOMIC_USIZE_INIT;

        let new_handle = next_handle.fetch_add(1, Ordering::Relaxed);

        let sysmsg = NetOp::Ip4TcpSocketRegisterAdv {
            ipv4:     0,       /* default */
            port:     port,
            tx:       tx_rx,
            rx:       rx_tx,
            handle:   new_handle,
            mtu:      mtu,
        };

        /*
            Let the system create the protected component of this socket.
        */
        net_tx.send(sysmsg);

        TcpSocket {
            connected: false,
            tx:        tx_tx,
            rx:        rx_rx,
            handle:    new_handle,
            net_tx:    net_tx,
        }
    }

    pub fn send(&self, data: Vec<u8>) {
        self.tx.send(TcpSocketMessage::Data(data));
        self.net_tx.send(NetOp::Ip4TcpSocketNotify { handle: self.handle });
    }

    pub fn sys_recv(&mut self) -> TcpSocketMessage {
        self.rx.recv().unwrap()
    }    
    
    /*
        SPEC:
            (1) We _shall_ not block.
            (2) We _shall_ report all reasons if data could not be returned.
            (3) Any status or error shall be reported before data is returned.

        TODO: develop better specification for error messages and
              their meaning for TcpSocketReadError
    */
    pub fn recv(&mut self) -> Result<Vec<u8>, TcpSocketReadError> {
        loop {
            let result = self.rx.try_recv();
            println!("$$$ user side tcp socket got message");
            match result {
                Result::Err(error) => break,
                Result::Ok(sockmsg) => {
                    match sockmsg {
                        TcpSocketMessage::Data(v8) => {
                            return Result::Ok(v8);
                        },
                        TcpSocketMessage::Connected => {
                            self.connected = true;
                        },
                        TcpSocketMessage::Disconnected => {
                            return Result::Err(TcpSocketReadError::Disconnected);
                        },
                        _ => {
                            /*
                                TODO: implement any remaining messages
                            */
                            continue;
                        }
                    }
                }
            }
        }

        Result::Err(TcpSocketReadError::NoData)
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn connect(&self, dstip: u32, dstport: u16) {
        /*
            (1) Place the command onto the socket's system message queue.
            (2) Notify the system that the socket needs attention.
        */
        self.tx.send(TcpSocketMessage::Connect {
            dstip:   dstip,
            dstport: dstport,
        });
        self.net_tx.send(NetOp::Ip4TcpSocketNotify { handle: self.handle });
    }
}

impl TcpSocketSystem {
    pub fn new(
            dst_ip: u32, src_ip: u32,
            dst_mac: &Vec<u8>, src_mac: &Vec<u8>,
            dst_port: u16, src_port: u16,
            net_tx: Sender<NetOp>,
            tx: Sender<TcpSocketMessage>,
            rx: Receiver<TcpSocketMessage>,
            handle: usize,
            mtu: usize,
            def_gw_mac6: &Vec<u8>,
    ) -> TcpSocketSystem {
        TcpSocketSystem {
            txstate:      TcpChannelState::Disconnected,
            rxstate:      TcpChannelState::Disconnected,
            ack:          0,
            seq:          100,
            dst_port:     dst_port,
            src_port:     src_port,
            dst_ip:       dst_ip,
            src_ip:       src_ip,
            dst_mac:      dst_mac.clone(),
            src_mac:      src_mac.clone(),
            tx:              tx,
            rx:              rx,
            net_tx:       net_tx,
            handle:       handle,
            mtu:          mtu,
            holding:      Vec::new(),
            def_gw_mac6:  def_gw_mac6.clone(),
        }
    }

    pub fn get_handle(&self) -> usize {
        self.handle
    }

    pub fn matches_packet(&self, pkt: &EthIp4TcpPacket) -> bool {
        if self.dst_port == pkt.read_tcp_port_src() &&
            self.src_port == pkt.read_tcp_port_dst() &&
            self.dst_ip == pkt.read_ip_src() &&
            self.src_ip == pkt.read_ip_dst() {
                true
        } else {
            false
        }
    }

    pub fn get_source_port(&self) -> u16 {
        self.src_port
    }

    pub fn onpacket(&mut self, pkt: EthIp4TcpPacket) {
     println!("tcp socket is processing message");

     if pkt.read_tcp_flags() & 0x10 != 0 {
         self.txstate = TcpChannelState::Connected;
         self.tx.send(TcpSocketMessage::Connected);
     }

     if pkt.read_tcp_flags() & 0x02 != 0 {
         self.rxstate = TcpChannelState::Connected;
         /*
             If they are going to transmit stuff. Then we
             need to grab their initial sequence.
         */
         self.ack = pkt.read_tcp_sequence() + 1;
         let cur_ack = self.ack;
         self.send_ack(cur_ack);
     }

     if pkt.read_tcp_flags() & 0x01 != 0 {
         self.rxstate = TcpChannelState::Disconnected;
         self.tx.send(TcpSocketMessage::EndOfStream);
         self.ack += 1;
         let cur_ack = self.ack;
         self.send_ack(cur_ack);
     }

     if pkt.read_tcp_flags() & 0x04 != 0 {
         match self.rxstate {
             TcpChannelState::Connected => self.tx.send(TcpSocketMessage::EndOfStream).unwrap(),
             _ => (),
         }
         self.rxstate = TcpChannelState::Disconnected;
         self.txstate = TcpChannelState::Disconnected;
         self.tx.send(TcpSocketMessage::Disconnected);
     }

     /*
         Is there any data attached? Let us read it into our incoming
         buffer and also acknowledge the data.

         seq
         ack
     */


     let data_offset = pkt.read_tcp_offset() + pkt.read_tcp_hdrlen() as usize * 4;

     println!("tcp_offset:{} data_offset:{} hdrlen:{} pkt.len():{}",
         pkt.read_tcp_offset(),
         data_offset,
         pkt.read_tcp_hdrlen() * 4,
         pkt.len()
     );

     if data_offset >= pkt.len() {
         return;
     }
     
     /*
        This is _very_ important. At times there can be extra data after the end of the
        IP payload. If we use the actual packet size read then we will consider data at
        the end of the packet part of the TCP/IP payload which is not actual payload.
        
        The source of these extra bytes are unknown. They could be from the system that
        hands us the packets, the network card, or from the actual remote system.
     */
     let last_ip_payload_byte = pkt.read_ip_total_length() as usize + pkt.read_ip_offset() as usize;

     let payload = pkt.data.readu8i(data_offset, last_ip_payload_byte - data_offset);

     println!("PAYLOAD:{}", payload.len());

     /*
         If this does not match out expected acknowledgement value,
         then let us store it away, and wait for the missing piece.
     */
     if pkt.read_tcp_sequence() != self.ack {
         println!("packet out of order; delaying pkt.seq{} self.ack:{}", pkt.read_tcp_sequence(), self.ack);
         /*
             Go ahead and let the remote end know that we received this packet.

             TODO: Is this correct? Should I instead only acknowledge the packets
                   in the correct order.
         */
         self.send_ack(pkt.read_tcp_sequence() + payload.len() as u32);

         self.holding.push(TcpSocketHeldPacket {
             seq:    pkt.read_tcp_sequence(),
             buf:    payload,
         });
         return;
     }

     self.ack += payload.len() as u32;

     println!("@@@ [tcp-socket] sent TX message with payload");
     self.tx.send(TcpSocketMessage::Data(payload));

     /*
         Acknowledge the data.

         OPTIMIZE: We could tag on a payload if we have data that needs to
                   be sent out.
     */
     let cur_ack = self.ack;
     self.send_ack(cur_ack);

     /*
         We know this was the next expected. Now run back through
         any packets that were in holding/limbo and see if we can
         push them through to the user code.
     */
     let mut keep_going: i32 = 0;
     while keep_going > -1 {
         keep_going = -1;
         let holding_len = self.holding.len();
         for hndx in 0..holding_len {
             let heldpkt = &self.holding[hndx];
             if heldpkt.seq == self.ack {
                 keep_going = hndx as i32;
                 break;
             }
         }
         if keep_going > -1 {
             let tmp = self.holding.remove(keep_going as usize);
             /*
                 Advance our actual acknowledgement value.
             */
             self.ack += tmp.buf.len() as u32;
             /*
                 These have already had an acknowledgement sent. So
                 just push them through to the user code in the correct
                 order and remove them from limbo.
             */
             self.tx.send(TcpSocketMessage::Data(tmp.buf));
         }
     }
     /*
         At this point our acknowledgement should have been caught up as
         much as possible. We may still be missing packets and therefore
         there may still be packets in holding/limbo. The next packet will
        start the process over.
     */
    }
    pub fn onnotify(&mut self) {
        loop {
            let result = self.rx.try_recv();
            match result {
                Result::Err(error) => break,
                Result::Ok(sockmsg) => {
                    match sockmsg {
                        TcpSocketMessage::Data(data) => {
                            /*
                                We may need to chop this up to stay under
                                the MTU, since currently the IP layer does
                                below us does not support fragmentation.
                            */
                            let chunk_count = data.len() / self.mtu;
                            let chunk_slack = data.len() % self.mtu;
                            for chunk in data.chunks(self.mtu) {
                                self.send_data(chunk);
                            }
                        },
                        TcpSocketMessage::Connect {
                            dstip,
                            dstport
                        } => {
                            self.dst_mac = self.def_gw_mac6.clone();
                            self.dst_ip = dstip;
                            self.dst_port = dstport;
                            self.try_connect();
                        },
                        TcpSocketMessage::Disconnect => {
                            /* TODO: implement */
                        },
                        _ => (),
                    }
                }
            }
        }
    }
    pub fn send_ack(&mut self, ack: u32) {
        let mut pkt = EthIp4TcpPacket::default();

        pkt.write_eth_mac_src(&self.src_mac);
        pkt.write_eth_mac_dst(&self.dst_mac);
        pkt.write_ip_src(self.src_ip);
        pkt.write_ip_dst(self.dst_ip);
        pkt.write_tcp_port_src(self.src_port);
        pkt.write_tcp_port_dst(self.dst_port);
        pkt.write_tcp_flags(0x10);
        pkt.write_tcp_acknowledge(ack);
        pkt.write_tcp_sequence(self.seq);

        pkt.compute_ip_checksum();
        pkt.compute_tcp_checksum();

        let mut data = pkt.get_data();

        self.net_tx.send(NetOp::SendEth8023Packet(data));
    }
    pub fn send_data(&mut self, data: &[u8]) {
        let mut pkt = EthIp4TcpPacket::default();

        pkt.write_eth_mac_src(&self.src_mac);
        pkt.write_eth_mac_dst(&self.dst_mac);
        pkt.write_ip_src(self.src_ip);
        pkt.write_ip_dst(self.dst_ip);
        pkt.write_tcp_port_src(self.src_port);
        pkt.write_tcp_port_dst(self.dst_port);
        /*
            Set PUSH flag to tell the remote machine that it
            needs to provide the data to application.

            We always acknowledge even if it is a duplicate
            acknowledgement, unless the receiving channel has
            not been setup by the remote end.
        */
        match self.rxstate {
            TcpChannelState::Connected => {
                pkt.write_tcp_acknowledge(self.ack);
                pkt.write_tcp_flags(0x18);
            },
            _ => {
                pkt.write_tcp_acknowledge(0x00);
                pkt.write_tcp_flags(0x08);
            },
        }

        pkt.write_tcp_sequence(self.seq);

        let tcp_offset = pkt.read_tcp_offset();
        let tcp_hdrlen = pkt.read_tcp_hdrlen();

        pkt.data.writeu8is(tcp_offset + (tcp_hdrlen as usize) * 4, data);

        let ip_new_total_length = pkt.read_ip_total_length() + data.len() as u16;

        pkt.write_ip_total_length(ip_new_total_length);

        pkt.compute_ip_checksum();
        pkt.compute_tcp_checksum();

        let mut data = pkt.get_data();

        self.seq += data.len() as u32;

        println!("socket sending data!!!");

        self.net_tx.send(NetOp::SendEth8023Packet(data));
    }
    pub fn try_connect(&mut self) {
        let mut pkt = EthIp4TcpPacket::default();

        pkt.write_eth_mac_src(&self.src_mac);
        pkt.write_eth_mac_dst(&self.dst_mac);
        pkt.write_ip_src(self.src_ip);
        pkt.write_ip_dst(self.dst_ip);
        pkt.write_tcp_port_src(self.src_port);
        pkt.write_tcp_port_dst(self.dst_port);
        pkt.write_tcp_flags(0x2);
        pkt.write_tcp_sequence(self.seq);
        pkt.write_tcp_acknowledge(self.ack);

        pkt.compute_ip_checksum();
        pkt.compute_tcp_checksum();

        self.txstate = TcpChannelState::Connecting;

        let mut data = pkt.get_data();

        println!("pkt.get_data.len():{}", data.len());

        self.seq += 1;

        self.net_tx.send(NetOp::SendEth8023Packet(data));
    }
}
