/*
    This contains a standalone primitive network system.

    TODO:
        The EthIp4TcpPacket needs to be generalized and the dependency
        of module tcp on this needs to be eliminated so that it can become
        more agnostic to as much of the underlying layers as possible. Also,
        we need to become more agnostic to it also. So that our worker which
        shovels data between the NIC can provide us data in a more general
        format and receive data in a more general format.

        #1 19,891,803,000
        #2 16,298,080,000

*/
extern crate std;
extern crate rand;
extern crate time;

mod packets;
mod tcp;
pub mod mysql;

pub use self::time::precise_time_ns;

use std::thread::JoinHandle;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread;
use std::mem::transmute_copy;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::pcap;
use super::pcap::Device;
use super::pcap::Active;

pub use super::common::SuperVec;

pub use self::tcp::TcpSocketMessage;
pub use self::tcp::TcpSocketSystem;
pub use self::tcp::TcpSocket;
pub use self::tcp::TcpSocketReadError;

pub use self::packets::EthIp4TcpPacket;

//pub use self::mysql::MySQLConnection;


pub enum NetOp {
   /*
     Notify the system to perform an orderly shutdown, and then
     let us know when it had been completed.
   */
   Shutdown,
	/*
		Notify the system that the socket needs attention.
	*/
	Ip4TcpSocketNotify {
			handle:     usize
	},
	/*
		Creates a TCP socket on top of IPv4.

		TODO: abstract away v4 - to support v6
	*/
	Ip4TcpSocketRegisterAdv {
		ipv4: 		u32,
		port: 		u16,
		tx: 		Receiver<TcpSocketMessage>,
		rx:         Sender<TcpSocketMessage>,
		handle:		usize,
		mtu:        usize,
	},
    Ip4TcpSocketRegister {
        tx: 		Receiver<TcpSocketMessage>,
        rx:         Sender<TcpSocketMessage>,
        handle:		usize,
    },
	/*
		TODO: abstract underlying link layer
	*/
	Eth8023Packet (Vec<u8>),
	/*
		TODO: change this to drop the underlying link layer protocol 802.3

		For the time being in order to stay on track I am going to leave
		this then drop it later. I need to rework the code I have for building
		packets to not be monolithic (hence EthIp4TcpPacket). Once I remove that
		monolithic type and improve encapsulation I will drop this, and let the
		net worker handle filling in the lower layers.
	*/
	SendEth8023Packet (Vec<u8>),
}

fn worker_net_handle_packet_8023(
	net_tx: &Sender<NetOp>,
	pkt: EthIp4TcpPacket,
	local_mac: &Vec<u8>,
	local_ipv4: u32,
	tcpsockets: &mut Vec<TcpSocketSystem>
	) {
	/*
		To us?

		If using pcap then we _can_ end up with packets
		headed to other systems. We could technically
		ignore this and use the IP destination check
		to filter those out. That would be faster but
		it is more proper to go ahead and filter it here.

		It would be faster since we would do a single 32-bit
		comparison instead of two 32-bit operations (6 out of 8 bytes).

		Also, pcap may support filters, or even have the ability to turn
		off promiscuous mode.
	*/
	//if pkt.read_eth_mac_dst() != local_mac {
	//	return;
	//}

	/* ARP ? */
	if pkt.read_eth_type() == 0x806 {
		//println!("got ARP");
		/*
			Is this a request?
		*/
		if pkt.read_arp_opcode() == 1 {
			//println!("got ARP request");
			/*
				Is it for our local IPv4 address?
			*/
			if pkt.read_arp_target_ipv4() == local_ipv4 {
				//println!("ARP request target ipv4 matches ours");
				/*
					Build and send a reply to let the sender know
					who we are on the Ethernet layer
				*/
				let arp_reply = EthIp4TcpPacket::arp_reply(
					local_mac,
					&pkt.read_arp_sender_mac6(),
					local_ipv4,
					pkt.read_arp_sender_ipv4()
				);

				/*
					Send to the worker so it can transmit the packet. We
					could have had a direct reference to the packet interface
					used here, but that would create hard dependencies at the
					gain of some efficiency, but I felt more flexibility was
					needed. So we use the `net_tx` channel to fabricate a command
					to send a packet.
				*/
				//println!("send ARP reply as {}", local_ipv4);
				net_tx.send(NetOp::SendEth8023Packet(arp_reply.get_data()));
				return;
			}
		}
		return;
	}

	/* only IP */
	if pkt.read_eth_type() != 0x800 as u16 {
		//println!("eth type not 0x800");
		return;
	}

	/* only version 4 */
	if pkt.read_ip_version() != 4 {
		//println!("ip version not 4");
		return;
	}

	/* only 20 byte header (non-compliant with RFC) */
	if pkt.read_ip_hdrlen() != 5 {
		//println!("ip header not correct size");
		return;
	}

	/* to our IP address? */
	//if pkt.read_ip_dst() != local_ipv4 {
	//	return;
	//}

	/* only TCP */
	if pkt.read_ip_protocol() != 6 {
		//println!("ip protocol not tcp");
		return;
	}

	/*
		We now know that we _can_ handle this packet
		and we know that it is addressed to us. Now,
		we need to figure out what we need to do with
		it and how to handle it.
	*/

	//println!("got ip4/tcp packet");

	/*
		downloading power point comes as a zip file

		creationtoday.org



		Can we match this up with a current TCP connection
		instance?
	*/
	//println!("trying to match packet with socket");
	for tcpsocket in tcpsockets.iter_mut() {
        if tcpsocket.matches_packet(&pkt) {
		    /*
		    	This is matched.

		    	TODO: match on IP identification field also?
		    */

		    //println!("packet matched with socket");
		    tcpsocket.onpacket(pkt);
			 return;
		}
	}
}

/*
	This is intended to run as a thread. It handles the entire
	supported network stack. It can handle the creation, destruction,
	and exchange of data over supported channels.

	At the moment only the 802.3/IPV4/TCP stack is supported.
*/
fn worker_net(
        local_mac: Vec<u8>, local_ipv4: u32,
        net_tx: Sender<NetOp>, rx: Receiver<NetOp>, tx: Sender<NetOp>,
        def_gw_mac6: Vec<u8>
    ) {
    // TODO: need to check this and give useful output to diagnose the problem
	let mut cap = Box::new(Device::lookup().unwrap().open().unwrap());

	let mut tcpsockets: Vec<TcpSocketSystem>;

	tcpsockets = Vec::new();

	/*
		Just a terrible hack. But, to not do this would have required
		patching the pcap crate or building my own bindings to libpcap
		and that would take a good amount of time during this prototype
		stage.

		We have basically thrown out the safety that Rust ensures with
		regard to the pcap crate. The crate did not provide the ability
		to clone or duplicate the handle and therefore it may not be
		safe for concurrent usage. We have basically said.. We know what
		we are doing now give us a copy of the handle.

		Also, I have used a Box which is essentially a single owner pointer
		so that when I make the copy below I do not copy the pcap::Capture
		object, but instead copy the Box (which is a pointer).

		I did not use a Rc because I can not move it into the contex of
		another thread. I did not use an Arc because it becomes immutable
		and the methods on pcap::Capture need an immutable reference to
		it. I could have used a Mutex but it would cause me to block on it
		in order to call a method.

		TODO: correct this with safe code
	*/
	let mut cap_clone: Box<pcap::Capture<pcap::Active>>;
	unsafe {
		cap_clone = std::mem::transmute_copy::<Box<pcap::Capture<pcap::Active>>, Box<pcap::Capture<pcap::Active>>>(&cap);
	}

	/*
		The sole job of this thread is the manage the transmission
		of outgoing data. I had to make a seperate thread for transmission
		because I the library below I am using to recieve packets will
		keep us blocked if no packets arrive preventing us from sending
		any data.
	*/
	let net_tx_clone = net_tx.clone();
	
	let shutdown: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
	let shutdown_copy: Arc<AtomicUsize> = shutdown.clone();

	let net_worker_tx = thread::spawn(move || {
	    // Initialize the periodic work timer start time. 
	    let mut tost = precise_time_ns();
	    
		loop {
			let op = rx.recv().unwrap();
			/*
				This loop:
					- processes incoming packets
						= handle connection requests (if supported)
					- processes incoming commands
						= commands to create connections
						= commands to send raw packets
			*/
			let curtime = precise_time_ns();
            if curtime - tost > 60 {
                // All TCP sockets shall do any periodic work needed.
                for tcpsocket in tcpsockets.iter_mut() {
                    tcpsocket.periodic_work(curtime);
                }
                tost = curtime;	
            }
			
			//println!("[net-worker] processing message");
			match op {
			   NetOp::Shutdown => {
			       /*
			           Shutdown, and also tell any other threads that we
			           control that they also need to shutdown.
			       */
			       shutdown_copy.fetch_add(1, Ordering::Relaxed);
			       //println!("[net-worker] shutdown");
			       /*
			         At the moment I used a hack to duplicate a pointer to
			         the PCAP object, however, that object may have a routine
			         that is executed on release. Since I hold a duplicate 
			         pointer which makes Rust's model unsafe we need to simply
			         forget about it to keep from running that twice and causing
			         a crash.
			         
			         TODO: find a way to work around this hack
			       */
			       unsafe {
			         std::mem::forget(cap_clone);
			       }
			       return;
			   },
            /*
                TODO: remove dependency, or add interface that is not
                      dependant on 802.3 (Ethernet II framing)
            */
				NetOp::SendEth8023Packet(v8) => {
					//println!("NetOp.. sent packet {}:{}", v8[0x0c], v8[0x0d]);
					cap_clone.sendpacket(v8.as_slice());
				},
				NetOp::Eth8023Packet(v8) => {
					worker_net_handle_packet_8023(
						&net_tx_clone,
						EthIp4TcpPacket::from_vec(&v8),
						&local_mac,
						local_ipv4,
						&mut tcpsockets
					);
				},
                /*
                    Let the system know that the socket needs to be serviced.

                    This may involve there being a message to the socket that needs
                    to be processed such as data to be transmitted.
                */
				NetOp::Ip4TcpSocketNotify { handle } => {
					/*
						TODO: improve collection to use handle
					*/
					for tcpsocket in tcpsockets.iter_mut() {
						if tcpsocket.get_handle() == handle {
							/*
								Service the socket.
							*/
							tcpsocket.onnotify(curtime);
							break;
						}
					}
				},
                /*
                    This was added to move selection of local port to this system
                    code. This simplifies the user calling code from not having to
                    have a mechanism to determine a free local port. This makes the
                    user interface safer to use and more secure.
                */
                NetOp::Ip4TcpSocketRegister {
                    tx,
                    rx,
                    handle,
                } => {
                    let __net_tx_clone = net_tx_clone.clone();

                    // Find an unused local port.
                    let mut was_good = true;
                    let mut local_port;
                    loop {
                        local_port = rand::random::<u16>();
                        was_good = true;
                        for tcpsocket in tcpsockets.iter() {
                            if tcpsocket.get_source_port() == local_port {
                                was_good = false;
                                break;
                            }
                        }
                        if was_good {
                            break;
                        }
                    }

                    if !was_good {
                        /*
                            TODO: implement message and send message alerting socket that it could
                                  not be created; skipping this to reduce development time for class
                                  project
                        */
                        println!("[net:system:Ip4TcpSocketRegister] could not get free local port");
                        return;
                    }

                    println!("[net:system:Ip4TcpSocketRegister] selected local port {}", local_port);

					let mut tcpsocket = TcpSocketSystem::new(
						0,
						local_ipv4,
						&vec![0, 0, 0, 0, 0, 0],
						&local_mac,
						0,
						local_port,
						__net_tx_clone,
						rx,
						tx,
						handle,
                  /* TODO: implement fragmentation support for IP and fix this */
						500,
                  &def_gw_mac6,
					);

					tcpsockets.push(tcpsocket);
            },
            /*
                For a secure environment this needs to disappear. I have left
                it since it was the original command to create a socket, and it
                offers some flexibility and experimentation.

                TODO: for secure environment have this removed at compile time
            */
			NetOp::Ip4TcpSocketRegisterAdv {
				ipv4,
				port,
				tx,
				rx,
				handle,
				mtu,
			} => {
				let __net_tx_clone = net_tx_clone.clone();
				let mut tcpsocket = TcpSocketSystem::new(
					0,
					local_ipv4,
					&vec![0, 0, 0, 0, 0, 0],
					&local_mac,
					0,
					port,
					__net_tx_clone,
					rx,
					tx,
					handle,
					mtu,
                    &def_gw_mac6,
				);

				tcpsockets.push(tcpsocket);
			},
	      }
		}
	});

	while let Some(packet) = cap.next() {
	   if shutdown.load(Ordering::Relaxed) > 0 {
	       break;
	   }	    
	    
		//println!("recv packet");
		let mut v8: Vec<u8> = Vec::new();
		/*
			This function is still unstable:
				`v8.clone_from_slice(packet.data);`

			TODO: use it when it becomes stable
		*/
		for x in 0..packet.data.len() {
			v8.push(packet.data[x]);
		}

		/*
			If the remote end crashes we will crash by calling
			unwrap here. This assures that everything terminates.
		*/
		net_tx.send(NetOp::Eth8023Packet(v8)).unwrap();
	}

	println!("net thread exiting");
}


pub struct Net {
    tx:             Sender<NetOp>,
    rx:             Receiver<NetOp>,
    worker_thread:  JoinHandle<()>,
}

impl Net {
    pub fn recv(&self) -> NetOp {
        self.rx.recv().unwrap()
    }    
    
    pub fn shutdown(self) {
        println!("[net::Net::shutdown] doing shutdown procedure.. <not implemented>");
        self.tx.send(NetOp::Shutdown);
        self.worker_thread.join();
    }

    pub fn new_tcp_socket_ex(&self, local_port: u16, mdtu: usize) -> TcpSocket {
        TcpSocket::new_adv(self.tx.clone(), local_port, mdtu)
    }

    pub fn new_tcp_socket(&self) -> TcpSocket {
        TcpSocket::new(self.tx.clone())
    }
    pub fn clone_tx_channel(&self) -> Sender<NetOp> {
        self.tx.clone()
    }
}

/*
	This will start a network using the specified MAC address and IP version 4 address.
*/
pub fn new_net(local_mac6: Vec<u8>, local_ipv4: u32, def_gw_mac6: Vec<u8>) -> Net {
	let (tx, __rx) = channel::<NetOp>();
	let (__tx, rx) = channel();
	let txclone = tx.clone();

    Net {
        tx:             tx,
        rx:             rx,
        worker_thread:  thread::spawn(move || {
    	      println!("running thread");
    	      worker_net(local_mac6, local_ipv4, txclone, __rx, __tx, def_gw_mac6);
    	}),
    }
}
