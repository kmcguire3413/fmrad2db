///! Implements the TCP socket 
///!
///! _This module is currently directly manipulates the entire
///! TCP/IP stack including the hardware level frame. This is a
///! current issue. It is hoped that code refactoring can move
///! and abstract this._
///!
///! # Issues
///!   * https://github.com/kmcguire3413/fmrad2db/issues/1

use std::sync::mpsc::{Sender, Receiver, channel, TryRecvError};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

use std::mem::swap;
use super::NetOp;
use super::packets::EthIp4TcpPacket;
use super::precise_time_ns;

/// State of the TCP channel.
pub enum TcpChannelState {
    Connecting,
    Connected,
    Disconnected,
}


/// A packet that has been received from the remote machine not in the
/// correct order, and it is awaiting the data that comes before it.
pub struct TcpSocketHeldPacket {
    seq:                            u32,
    buf:                            Vec<u8>,
}

/// A packet that has not been acknowledged by the remote machine,
/// and is held in limbo awaiting the possibility of retransmission. 
pub struct HeldOutPacket {
    seq:                            u32,
    buf:                            Vec<u8>,
    timerefns:                      u64,
}

/// The system side instance of the TCP socket.
pub struct TcpSocketSystem {
    txstate:                TcpChannelState,
    rxstate:                TcpChannelState,
    dst_port:               u16,
    src_port:               u16,
    dst_ip:                 u32,
    src_ip:                 u32,
    src_mac:                Vec<u8>,
    dst_mac:                Vec<u8>,
    ack:                    u32,
    seq:                    u32,
    mtu:                    usize,
    handle:                 usize,
    outholding:             Vec<HeldOutPacket>,
    holding:                Vec<TcpSocketHeldPacket>,
    tx:                     Sender<TcpSocketMessage>,
    rx:                     Receiver<TcpSocketMessage>,
    net_tx:                 Sender<NetOp>,
    def_gw_mac6:            Vec<u8>,
    timeout_marker:         u64,
}

pub enum DisconnectReason {
    NotSpecified,
    InternalError,
    Timeout,
    Remote,
    Local,
}

/// A message structure that is used to communicate
/// data and control messages to and from the user
/// code.
///
/// # Issues
///   * https://github.com/kmcguire3413/fmrad2db/issues/6
pub enum TcpSocketMessage {
    Data(Vec<u8>),
    Connect { dstip: u32, dstport: u16 },
    Disconnect,
    Error,
    Disconnected { reason: DisconnectReason },
    Connected,
    EndOfStream,
}

/// The user side TCP socket instance.
pub struct TcpSocket {
    handle:                usize,
    connected:             bool,
    pub tx:                Sender<TcpSocketMessage>,
    pub rx:                Receiver<TcpSocketMessage>,
    net_tx:                Sender<NetOp>,
}

#[derive(Debug)]
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

    pub unsafe fn sys_recv(&mut self) -> TcpSocketMessage {
        self.rx.recv().unwrap()
    }    
    
    /// Receive any data or control messages on the socket without blocking.
    ///
    /// Contract:
    ///   * shall not block
    ///   * may return control message instead of data
    ///   * shall report all reasons data could not be returned
    ///   * message will be returned in order received        
    pub fn recv(&mut self) -> TcpSocketMessage {
        self.recvex(false)
    }
    
    /// Receive any data or control message on the socket, or block until
    /// data or a control message arrives.
    pub fn recvblock(&mut self) -> TcpSocketMessage {
        self.recvex(true)
    }
    
    /// Provides ergonomic adapter between blocking and non-blocking
    /// channel reading from system side socket structure.
    fn sockrecv(&mut self, block: bool) -> TcpSocketMessage {
        if block {
            let result = self.rx.recv();
            match result {
                Result::Err(error) => TcpSocketMessage::Error,
                Result::Ok(sockmsg) => sockmsg,
            }
        } else {
            let result = self.rx.try_recv();
            match result {
                Result::Err(error) => match error {
                    TryRecvError::Empty => TcpSocketMessage::EndOfStream,
                    TryRecvError::Disconnected => TcpSocketMessage::Disconnected { 
                        reason: DisconnectReason::InternalError
                    }
                }, 
                Result::Ok(sockmsg) => sockmsg,
            }
        }
    }
    
    /// Provides ability to receive socket data or message with argument to
    /// specify if we shall block until data or control message arrives.
    ///
    /// # Panics
    /// This method will panic if it receives any message that was not intended
    /// to be received for debugging purposes.
    pub fn recvex(&mut self, block: bool) -> TcpSocketMessage {
        let mut sockmsg = self.sockrecv(block);
        match sockmsg {
            TcpSocketMessage::Data(v8) => TcpSocketMessage::Data(v8),
            TcpSocketMessage::Connected => {
                self.connected = true;
                sockmsg
            },
            TcpSocketMessage::Disconnected { reason } => {
                self.connected = false;
                TcpSocketMessage::Disconnected { reason: reason }
            },
            TcpSocketMessage::Connect {dstip, dstport } => panic!("[tcp-socket-user] got TcpSocketMessage::Connect"),
            TcpSocketMessage::Disconnect => panic!("[tcp-socket-user] got TcpSocketMessage::Connect"),
            TcpSocketMessage::Error => sockmsg,
            TcpSocketMessage::EndOfStream => sockmsg, 
        }
    }

    /// Denotes if the socket is under the impression that it is still connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Attempt a connection with the remote server.
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
    /// Create a new TCP socket system side instance. 
    ///
    /// This does not create the user side component of the socket, and
    /// for all intentions shall not. That component would normally inform
    /// the Net system of the need to create a socket and the Net would
    /// call this constructor.
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
            txstate:        TcpChannelState::Disconnected,
            rxstate:        TcpChannelState::Disconnected,
            ack:            0,
            seq:            100,
            dst_port:       dst_port,
            src_port:       src_port,
            dst_ip:         dst_ip,
            src_ip:         src_ip,
            dst_mac:        dst_mac.clone(),
            src_mac:        src_mac.clone(),
            tx:             tx,
            rx:             rx,
            net_tx:         net_tx,
            handle:         handle,
            mtu:            mtu,
            holding:        Vec::new(),
            outholding:     Vec::new(),
            def_gw_mac6:    def_gw_mac6.clone(),
            timeout_marker: precise_time_ns(),
        }
    }

    /// Return the unique handle used as an identifier for the socket.
    pub fn get_handle(&self) -> usize {
        self.handle
    }

    /// Check if packet is destined to this socket.
    ///
    /// # Issues 
    ///   * https://github.com/kmcguire3413/fmrad2db/issues/1
    /// 
    /// # Contract
    ///
    ///   * checks packet fields to match socket parameters
    ///   * may implement partial specification for stack
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

    /// Return the TCP source port used by this socket.
    pub fn get_source_port(&self) -> u16 {
        self.src_port
    }
    
    /// Called to allow the socket to do any periodic work.
    ///
    /// # Implementation Contract
    ///   * no guarantee on calling frequency or interval
    ///   * calling frequency and interval shall change
    ///   * shall return control as soon as possible
    ///
    /// # Contract
    ///   * `timeref` shall be in nanosecond units
    ///   * shall provide no useful functionality directly to the caller system
    ///   * owner of this socket shall call this periodically
    ///   * `timeref` shall be as accurate, _as possible_, in time units from last call
    pub fn periodic_work(&mut self, timerefns: u64) {
        // Check if enough time has elapsed that we need to re-transmit any packets
        // that have not been acknowledged by the remote machine.
        let mut outholding: Vec<HeldOutPacket> = Vec::new();
        
        swap(&mut outholding, &mut self.outholding);        
        
        for x in 0..outholding.len() {
            let item = &mut outholding[x];
            if timerefns - item.timerefns > 1000 * 1000 * 1000 * 10 {
                // Send the data with the correct sequence number and
                // update the time reference field.
                item.timerefns = timerefns;
                self.send_data_ex(item.buf.as_slice(), item.seq);
            }
        }        
        
        swap(&mut outholding, &mut self.outholding);
        
        // If the connection has been inactive for too long then we shall
        // drop the connection.
        if timerefns - self.timeout_marker > 1000 * 1000 * 1000 * 60 * 5 {
            match self.rxstate { 
                TcpChannelState::Connected => {
                    self.reset(DisconnectReason::Timeout);
                },
                _ => (),
            }
        }
    }    
    
    pub fn reset(&mut self, reason: DisconnectReason) {
        // The connection has an inactive period that exceeds the
        // specified limit, therefore, it shall be closed.
        self.send_reset();
        // Clear to prevent the remote end from exploiting any
        // code paths that cause the connection to continue to function.
        self.dst_ip = 0;
        self.dst_port = 0;
        // Set both channels to the disconnected state.
        self.txstate = TcpChannelState::Disconnected;
        self.rxstate = TcpChannelState::Disconnected;
        // Alert the user side of the socket to this change
        // in state of the socket and connection.
        self.tx.send(TcpSocketMessage::Disconnected{ reason: reason });        
    }

    /// Interprets a packet for data and control information.
    ///
    /// # Contract
    ///   * unsafe for untrusted input
    ///   * does _NOT_ fully check validity of the packet
    ///   * shall construct acknowledgement packets
    ///   * shall maintain TCP socket state
    pub fn onpacket(&mut self, pkt: EthIp4TcpPacket) {
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
         self.tx.send(TcpSocketMessage::Disconnected { reason: DisconnectReason::Remote });
     }

     // Is there any data attached? Let us read it into our incoming
     // buffer and also acknowledge the data.
     
     self.timeout_marker = precise_time_ns();
     
     // Let us read the acknowledgement and see if we can remove some packets
     // that are in outgoing limbo. We have to be aware that a single acknowledgement
     // can acknowledge multiple packets at once, therefore, a loop exists which matches
     // these and removes them.
     let rack = pkt.read_tcp_acknowledge();  
     let mut remndx: Option<usize> = Option::None;     
     let mut hsz = self.outholding.len();     
     
     // TODO: consider optimization of `outholding` to support efficient removal
     //       since at the moment this involves a substantial performance hit since
     //       all elements are shifted for each removal
     let mut x = 0;
     while x < hsz {
         let mut remit = false;

         {
             let item = &self.outholding[x];
             if rack > item.seq {
                 println!("got ack {} for packet {} removing it from limbo", rack, item.seq);
                 remit = true;
             }
         }
         
         if remit {
             self.outholding.remove(x);
             hsz -= 1;
         } else {
             x = x + 1;
         }
     }
     
     match remndx {
         Option::None => (),
         Option::Some(ndx) => { self.outholding.remove(ndx); },
     }
     
     // This is _very_ important. At times there can be extra data after the end of the
     // IP payload. If we use the actual packet size read then we will consider data at
     // the end of the packet part of the TCP/IP payload which is not actual payload.
     // 
     // The source of these extra bytes are unknown. They could be from the system that
     // hands us the packets, the network card, or from the actual remote system.
     
     let data_offset = pkt.read_tcp_offset() + pkt.read_tcp_hdrlen() as usize * 4;
     let last_ip_payload_byte = pkt.read_ip_total_length() as usize + pkt.read_ip_offset() as usize;

     if last_ip_payload_byte - data_offset <= 0 {
         return;
     }

     let payload = pkt.data.readu8i(data_offset, last_ip_payload_byte - data_offset);

     // If this does not match out expected acknowledgement value,
     // then let us store it away, and wait for the missing piece.
     
     if pkt.read_tcp_sequence() != self.ack {
         // This packet arrived out of order. We do not acknowledge it since our acknowledgement
         // would tell the remote end that we have received in order everything below this sequence
         // number. We shall only acknowledge packets in the correct order.
         // self.send_ack(pkt.read_tcp_sequence() + payload.len() as u32);

         self.holding.push(TcpSocketHeldPacket {
             seq:    pkt.read_tcp_sequence(),
             buf:    payload,
         });
         return;
     }

     self.ack += payload.len() as u32;

     self.tx.send(TcpSocketMessage::Data(payload));

     // We know this was the next expected. Now run back through
     // any packets that were in holding/limbo and see if we can
     // push them through to the user code.
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
             // Advance our actual acknowledgement value.
             self.ack += tmp.buf.len() as u32;
             self.tx.send(TcpSocketMessage::Data(tmp.buf));
         }
     }

     // Let the remote end know that we have the sequence up to this point
     // and we do not require any resends.
     let curack = self.ack;
     self.send_ack(curack);     
    }
    /// Intended to allow socket to process internal channels for commands
    /// and data that be waiting.
    ///
    /// The data and commands are sent from the user side instance of the
    /// socket a channel. This function allows the network thread to allow
    /// _this socket_ to process that channel and any commands or data.
    ///
    /// # Contract
    ///   * `timerefns` shall be in nanoseconds
    ///   * caller shall attempt to only call when there are messages waiting to be read
    pub fn onnotify(&mut self, timerefns: u64) {
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
                                self.send_data(chunk, timerefns);
                            }
                        },
                        TcpSocketMessage::Connect {
                            dstip,
                            dstport
                        } => {
                            if self.dst_ip == dstip && self.dst_port == dstport && 
                               match self.txstate {
                                   TcpChannelState::Connecting => true,
                                   _ => false,
                               } {
                               // Just ignore this as it likely may be coming from
                               // a misbehaving user side program. If they truly desire
                               // to attempt connection again to the same remote machine
                               // that we are currently connecting to then it would be
                               // polite for us to get a disconnect and also for the 
                               // remote machine.      
                            } else {
                                self.dst_mac = self.def_gw_mac6.clone();
                                self.dst_ip = dstip;
                                self.dst_port = dstport;
                                self.timeout_marker = timerefns; 
                                self.try_connect();
                            }
                        },
                        TcpSocketMessage::Disconnect => {
                            self.reset(DisconnectReason::Local);
                        },
                        _ => (),
                    }
                }
            }
        }
    }
    
    /// Send an acknowledgement packet for the acknowledgment number provided.
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
    
    pub fn send_reset(&mut self) {
        let mut pkt = EthIp4TcpPacket::default();

        pkt.write_eth_mac_src(&self.src_mac);
        pkt.write_eth_mac_dst(&self.dst_mac);
        pkt.write_ip_src(self.src_ip);
        pkt.write_ip_dst(self.dst_ip);
        pkt.write_tcp_port_src(self.src_port);
        pkt.write_tcp_port_dst(self.dst_port);
        // TODO: Should we also set FIN or just RST?
        pkt.write_tcp_flags(0x05);
        // TODO: Is this acknowledgement number correct? Does it matter?
        pkt.write_tcp_acknowledge(self.ack);
        pkt.write_tcp_sequence(self.seq);

        pkt.compute_ip_checksum();
        pkt.compute_tcp_checksum();

        let mut data = pkt.get_data();

        self.net_tx.send(NetOp::SendEth8023Packet(data));        
    }
    
    /// Send a packet containing data.
    ///
    /// # Contract
    ///   * shall transmit data as soon as possible
    ///   * will not check if data exceeds network MTU
    ///   * shall update sequence number
    ///   * will modify local state of connection
    pub fn send_data(&mut self, data: &[u8], timerefns: u64) {
        // We need to store what we send, because it might not reach
        // the destination, therefore, we will need to resend it after
        // a specified amount of time has passed.
        let mut nbuf: Vec<u8> = Vec::with_capacity(data.len());
        nbuf.push_all(data);        
        self.outholding.push(HeldOutPacket {
            seq:        self.seq,
            buf:        nbuf,
            timerefns:  timerefns,
        });
        
        println!("added packet to outgoing limbo with seq {}", self.seq);
        let dataseq = self.seq;
        self.seq += data.len() as u32;        
        self.send_data_ex(data, dataseq);
    }
        
    /// Send a packet containing data with the specified sequence number.
    ///
    /// # Contract
    ///   * shall transmit data as soon as possible
    ///   * will not check if data exceeds network MTU
    ///   * shall use sequence number provided 
    ///   * _shall not_ modify local state of connection
    fn send_data_ex(&mut self, data: &[u8], seq: u32) {
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

        // Use the sequence number as the argument provided
        // to this function, since this function is used to
        // resend data.
        pkt.write_tcp_sequence(seq);

        let tcp_offset = pkt.read_tcp_offset();
        let tcp_hdrlen = pkt.read_tcp_hdrlen();

        pkt.data.writeu8is(tcp_offset + (tcp_hdrlen as usize) * 4, data);

        let ip_new_total_length = pkt.read_ip_total_length() + data.len() as u16;

        pkt.write_ip_total_length(ip_new_total_length);

        pkt.compute_ip_checksum();
        pkt.compute_tcp_checksum();

        println!("socket sequence is {} and data.len is {}", self.seq, data.len());
        
        println!("socket sequence is now {}", self.seq);

        //println!("socket sending data!!!");
        
        let mut data = pkt.get_data();
        self.net_tx.send(NetOp::SendEth8023Packet(data));
    }
    
    /// Sends a TCP packet with the synchronize flag set to attempt establishment
    /// of a connection.
    ///
    /// # Contract
    ///   * shall send a TCP packet with the SYN flag set as soon as possible
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
        self.rxstate = TcpChannelState::Connecting;

        let mut data = pkt.get_data();

        //println!("pkt.get_data.len():{}", data.len());

        self.seq += 1;

        self.net_tx.send(NetOp::SendEth8023Packet(data));
    }
}
