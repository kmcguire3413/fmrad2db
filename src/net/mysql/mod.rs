use super::{TcpSocket, TcpSocketMessage, Net};

struct MySQLPendingStatement {
	id:					usize,
	stmt_encoded: 		Vec<u8>,
}

struct MySQLConnection {
	user:               Vec<u8>,
	pass:               Vec<u8>,
	next_id:			usize,
	remote_ip:			u32,
	remote_port:		u16,
	conn_ready:         bool,
	socket:				TcpSocket,
	net_tx:				Sender<NetOp>,
	pending_statements: Vec<MySQLPendingStatement>,
	buffer:				Vec<u8>,
}

impl MySQLConnection {
	/*
		Return a new MySQL connection represented with this object.

		(1) Not required to actually establish connection.
		(2) Required to be able to establish connection when needed.
	*/
	pub fn new_with_ipv4_tcp(net: Net, remote_ip: u32, remote_port: u16, user: Vec<u8>, pass: Vec<u8>) {
		MySQLConnection {
			user:         user,
			pass:         pass,
			conn_ready:	  false,
			remote_ip:	  remote_ip,
			remote_port:  remote_port,
			socket:		  net.new_tcp_socket(),
			net_tx:		  net.clone_tx_channel(),
			next_id:      0,
		}
	}

	pub fn query(&mut self, statement: &str) -> usize {
		/*
			SPEC:
				(1) We _must_ conform to the encoding/charset specified by the server.

			TODO: Implement (1)
		*/
		let stmt_encoded = statement.bytes().collect();

		self.pending_statements.push(MySQLPendingStatement { stmt_encoded: stmt_encoded, id: self.next_id });

		self.next_id += 1;

		self.send_pending_query();
	}

	pub fn u8readuntil(s: &[u8], u: u8) -> Vec<u8> {
		let b: Vec<u8> = Vec::new();
		for x in 0..s.len() {
			if s[x] == u {
				break;
			}
			b.push(s[x]);
		}
		b
	}

	pub fn onpacket(&mut self, num: u8, pkt: &[u8]) {
		let op = pkt[0];

		match op {
			0x0a => {
				/* https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake */
				let version = MySQLConnection::u8readuntil(pkt[1..], 0);
				/* skipped connection id (4 bytes) */
				let auth_plugin_data = MySQLConnection::u8readuntil(pkt[1+version.len()+4..], 0);
				/* more, but this is all we need */

				/* forge our reply */
				let reply = SuperVec::new();

				/* https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse */
				/* mimicing protocol dump; lots of little flags here; capability flags */
				reply.writeu16le(0x00, 0xa605);
				reply.writeu16le(0x02, 0x000f);
				reply.writeu32le(0x06, 16777216);
				/* utf8 */
				reply.writeu8(0x0a, 0x21);
				/* username with null terminator */
				reply.writeu8i(0x0b, &self.user);
				let mut off = 0x0b + self.user.len();
				reply.writeu8i(off, 0);
				/* encode password */
				reply.writeu8(off + 0x01, self.pass.len() as u8);
				reply.writeu8i(off + 0x02, &self.pass);
				off += 0x02 + self.pass.len();
				/* TODO: fix this up... it is a UTF-8 string that says "mysql_native_password" with a
				         NULL (0x00) at the end..
				*/
				reply.writeu8i(off, vec![
					0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61,
					0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00
				]);
				self.socket.send(reply.get_data());
			},
			_ => (),
		}
	}

	pub fn tick(&mut self) {
		loop {
			let result = self.socket.recv();
			match result {
				Result::Err(err) => {
					match err {
						TcpSocketReadError::Disconnected => {
							self.conn_ready = false;
						},
						_ => (),
					}
				},
				Result::Ok(v8) => {
					/*
						TODO: think about optimization later if needed
					*/
					/*
						Place everything into a contigious buffer. This makes the code logic
						must easier.
					*/
					self.buffer.append(v8);

					/*
						Decode the data into MySQL packets. We may only have a partial packet, and
						we shall abort the decoding and place it into a buffer.
					*/
					let mut curndx: usize = 0;
					while curndx < buffer.len() {
						let pktlen = v8[curndx + 0] | (v8[curndx + 1] << 8) | (v8[curndx + 2] << 16);
						let pktnum = v8[curndx + 3];
						if curndx + pktlen + 3 + 1 > buffer.len() {
							break;
						}

						/*
							Grab a slice (view) of the buffer. This will help ensure safety that
							we do not under or over-read the buffer, and it is a very cheap operation.
						*/
						{
							let pkt = v8[curndx + 3 + 1..curndx + 3 + 1 + pktlen];
							self.onpacket(pktnum, pkt);
						}
						curndx += pktlen + 3 + 1;
					}

					/*
						Drop anything we have processed and used.
					*/
					self.buffer = self.buffer[curndx..].collect();
				},
			}
		}
	}

	pub fn send_pending_query(&mut self) {
		if !self.socket.is_connected() {
			self.socket.connect(self.remote_ip, self.remote_port);
			return;
		}

		if !self.conn_ready {
			self.tick();
			if !self.conn_ready {
				/*
					Authenticate.
				*/
			}
			return;
		}

	}
}