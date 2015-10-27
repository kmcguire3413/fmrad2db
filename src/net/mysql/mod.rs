// ALL RIGHTS RESERVED 2015 
// LEONARD KEVIN MCGUIRE JR. <kmcg3413@gmail.com>
// 242 EAST SKIPPER ROAD
// ECLECTIC, AL 36024
//
//! Provides the ability:
//!
//!   * connect remotely to MySQL server over TCP/IP protocol
//!   * execute remote queries on MySQL server and get results on arrival
//!
extern crate byteorder;

mod sha1;

use std::mem;
use std::sync::mpsc::{Sender, Receiver, channel};
use super::{TcpSocket, TcpSocketMessage, Net, SuperVec, NetOp, TcpSocketReadError};

/// The local representation and usable state of the server data.
///
/// The agnostic nature of these types, from MySQL server, was done
/// for optimization and ergonomic purposes.
///
///   * agnostic to the server MySQL data type
pub enum Field {
    i64(i64),
    String(String),
    Unknown,
}

/// The server interpreted type of the data.
pub enum ServerFieldType {
    Long,
    LongLong,
    String,
    VarString,
}

/// The locally interpreted type of the data from the server.
pub enum FieldType {
    Integer,
    String,
}

/// The header defines the field of a record.
pub enum FieldHeader {
    Normal {
        catalog:        Vec<u8>,
        database:       Vec<u8>,
        table:          Vec<u8>,
        origtable:      Vec<u8>,
        name:           Vec<u8>,
        origname:       Vec<u8>,
        charset:        u16,
        len:            u32,
        stype:          ServerFieldType,
        itype:          FieldType,
        flags:          u16,
        decimals:       u8,
    },
    Empty,                    
}

/// Represents a pending command.
pub enum PendingCommand {
    UseDatabase { schema: Vec<u8> },
    Query { querystring: Vec<u8> },
}

/// The series of fields that represent a single record, and any
/// additional information that can be provided for a single record.
pub struct Record {
    fields:     Vec<Field>,
}

/// The response structure represents the response from the server.
pub enum Response {
    /// There is no more information that can be provided, but
    /// the operation resulted in the generation of an error.
    ///
    ///   * more information may not be available because of partial implementation
    ///   * more information may not have been provided by the server
    ///   * this response may be generated locally (not from server)
    Error,
    /// The response was a set of records.
    ///
    ///   * may contain zero or more records
    ///   * records and fields are not checked for validity
    ///   * this response may be generated locally (not from server)
    Table { records: Vec<Record> },
    /// There is no more information that can be provided, but
    /// the operation was successful.
    ///
    ///   * more information may not be available because of partial implementation
    ///   * more information may not have been provided by the server
    ///   * this response may be generated locally (not from server)
    Success,
    /// The login was not successful.
    LoginError,
    /// The login was successful.
    LoginSuccess,
}

/// The MySQL connection instance memory structure.
pub struct MySQLConnection {
    user:               Vec<u8>,
    pass:               Vec<u8>,
    remote_ip:          u32,
    remote_port:        u16,
    connstate:          ConnectionState,
    socket:             TcpSocket,
    net_tx:             Sender<NetOp>,
    buffer:             Vec<u8>,
    responses:          Vec<Response>,
    // These affect the state of the construct in packet interpretation.
    pending_response:   u32,
    number_of_fields:   u8,
    field_headers:      Vec<FieldHeader>,
    pending_records:    Vec<Record>,
    pending_cmds:       Vec<PendingCommand>,
    pending_cmds_sent:  u32,
}

pub enum ConnectionState {
    Idle,
    Connecting,
    Connected,
    Ready
}

impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        match self {
            &ConnectionState::Connected => true,
            _ => false,
        }
    }
    pub fn is_idle(&self) -> bool {
        match self {
            &ConnectionState::Idle => true,
            _ => false,
        }
    }
}

pub enum SocketReadError {
    ChannelBroke
}

impl MySQLConnection {
    ///  Return a new MySQL connection represented with this object. The connection will
    ///  not be attempted until `tick` is called.
    ///
    ///  # Contract
    ///    * connection shall not be attempted until `tick` is called
    ///    * connection shall be re-established if and only if lost
    ///    * connection is not guaranteed to succeed
    ///    * query strings not executed shall be pending until connection is established
    pub fn new_with_ipv4_tcp(net: &Net, remote_ip: u32, remote_port: u16, user: Vec<u8>, pass: Vec<u8>) -> MySQLConnection {
        MySQLConnection {
            buffer:              Vec::new(),
            user:                user,
            pass:                pass,
            remote_ip:           remote_ip,
            remote_port:         remote_port,
            socket:              net.new_tcp_socket(),
            net_tx:              net.clone_tx_channel(),
            pending_response:    0,
            responses:           Vec::new(),
            number_of_fields:    0,
            field_headers:       Vec::new(),
            pending_records:     Vec::new(),
            pending_cmds:        Vec::new(),
            pending_cmds_sent:   0,
            connstate:           ConnectionState::Idle,
        }
    }
    
    /*
        This sends a MySQL packet, which is different from a normal 
        TCP socket packet. This packet has a special MySQL header
        attached and turns the TCP stream based protocol into a 
        packet based protocol.    
    
        Spec:
            (1) Will write packet length and packet number headers.
            (2) Take ownership of payload memory for optimization potential.
            (3) Send packet to the remote machine in reasonable time.
    */
    fn send_mysql_packet(&mut self, pktnum: u8, data: Vec<u8>) {
        let mut reply = SuperVec::new();
        reply.writeu24le(0, data.len() as u32);
        reply.writeu8(3, pktnum);
        reply.writeu8i(4, &data);
        self.socket.send(reply.get_data());                
    }
    
    fn send_cmd_use_database(&mut self, schema: &[u8]) {
        let mut pkt = SuperVec::new();
        pkt.writeu8(0x00, 0x02);
        pkt.writeu8is(0x01, schema);
        self.send_mysql_packet(0, pkt.get_data());
        self.pending_cmds_sent += 1;
    }
    
    fn send_cmd_query(&mut self, querystring: &[u8]) {
        let mut pkt = SuperVec::new();
        pkt.writeu8(0x00, 0x03);
        pkt.writeu8is(0x01, querystring);
        self.send_mysql_packet(0, pkt.get_data());
        self.pending_cmds_sent += 1;
    }
    
    /// Switch the current default database to the one specified by schema.
    ///
    /// # Contract
    ///   * error response may be immediately generated before function return
    ///   * command shall be executed on the server before response is pushed onto stack
    pub fn use_database(&mut self, schema: Vec<u8>) {    
        self.pending_cmds.push(PendingCommand::UseDatabase { schema: schema });
    }
    
    /// Execute a query string on the remote server. The response will be
    /// stored in the response stack. The response stack can be access using
    /// the appropriate function. 
    ///
    /// _This function does not cache any data, therefore,
    /// the query string is guaranteed to be transmitted to the server._
    ///
    /// # Contract
    ///   * no cache shall be used for query results
    ///   * query string shall be transmitted to the remote server for execution
    ///   * query may not be immediately executed
    ///   * query shall be executed by successive calling of tick; if not by call return
    ///   * responses shall be placed on stack in order this function is called
    ///   * query string shall not be checked for validity
    ///   * error type response may be generated immediately before return 
    pub fn query(&mut self, querystring: Vec<u8>) {
        self.pending_cmds.push(PendingCommand::Query { querystring: querystring });
    }
    
    /// Return the oldest response on the response stack. A response
    /// is a answer from the server. It is produced following any command
    /// and may be a simulated response that does not originate from the
    /// server.
    ///
    /// # Contract
    ///   * response may not be available 
    ///   * response is not checked for validity
    ///   * response may be an error
    pub fn pop_response(&mut self) -> Option<Response> {
        self.responses.pop()
    }

    fn onpacket(&mut self, pktnum: u8, pkt: &[u8]) {
        let pktsv = SuperVec::from_slice(pkt);
        
        let op = pkt[0];
        
        // <rec-count>
        
        println!("[mysql] got sub-packet with op {}", op);
        
        if self.pending_cmds_sent > 0 && self.pending_cmds.len() > 0 && pktnum > 0 {
            if op == 0xff {
                // The pending response was an error.
                self.responses.push(Response::Error);
                self.pending_cmds.remove(0);
                self.pending_cmds_sent -= 1;
                return;
            } 
            
            if pktnum == 1 && pktsv.readu8(0) == 0 {
                self.responses.push(Response::Success);
                self.pending_cmds.remove(0);
                self.pending_cmds_sent -= 1;
                return;
            }
            
            if pktnum == 1 {
                self.number_of_fields = pktsv.readu8(0);
                for x in 0..self.number_of_fields {
                    self.field_headers.push(FieldHeader::Empty);
                }
                return;
            }
            
            if pktnum > 1 && pktnum < 2 + self.number_of_fields {
                let mut sz: usize = 0;
                let mut pos: usize = 0;
                
                sz = pktsv.readu8(pos) as usize;
                let catalog = pktsv.readu8i(pos + 1, sz);
                pos += sz + 1;
                sz = pktsv.readu8(pos) as usize;
                let database = pktsv.readu8i(pos + 1, sz);
                pos += sz + 1;
                sz = pktsv.readu8(pos) as usize;
                let table = pktsv.readu8i(pos + 1, sz);
                pos += sz + 1;
                sz = pktsv.readu8(pos) as usize;
                let origtable = pktsv.readu8i(pos + 1, sz);
                pos += sz + 1;                
                sz = pktsv.readu8(pos) as usize;
                let name = pktsv.readu8i(pos + 1, sz);
                pos += sz + 1;
                sz = pktsv.readu8(pos) as usize;
                let origname = pktsv.readu8i(pos + 1, sz);
                pos += sz + 1;
                                
                pos += 1;
                
                let charset = pktsv.readu16le(pos);
                pos += 2;
                
                let flen = pktsv.readu32le(pos);
                pos += 4;
                
                let ftype = pktsv.readu8(pos);
                pos += 1;
                
                let flags = pktsv.readu16le(pos);
                pos += 2;
                
                let decimals = pktsv.readu8(pos);                
                
                self.field_headers[(pktnum - 2) as usize] = FieldHeader::Normal {
                    catalog:        catalog,
                    database:       database,
                    table:          table,
                    origtable:      origtable,
                    name:           name,
                    origname:       origname,
                    charset:        charset,
                    len:            flen,
                    stype:          match ftype {
                        0x03 => ServerFieldType::Long,
                        0xfe => ServerFieldType::String,
                        0x08 => ServerFieldType::LongLong,
                        0xfd => ServerFieldType::VarString,
                        _ => panic!("unknown mysql field type"),
                    },
                    itype:           match ftype {
                        0x03 => FieldType::Integer,
                        0xfe => FieldType::String,
                        0x08 => FieldType::Integer,
                        0xfd => FieldType::String, 
                        _ => panic!("unknown mysql field type"),
                    },
                    flags:          flags,
                    decimals:       decimals,                    
                };                  
                return;
            }
            
            if pktnum == 2 + self.number_of_fields {
                // Should be an EOF marker.
                if pktsv.readu8(0) != 0xfe {
                    panic!("[mysql] expected EOF marker 0xfe");
                }
                return                
            }
            
            if pktsv.readu8(0) == 0xfe {
                // We should have received the last record, therefore,
                // let us push these records as a response for the user
                // code to fetch, and clear out state machine.
                let mut empty_records_vec: Vec<Record> = Vec::new();
                mem::swap(&mut self.pending_records, &mut empty_records_vec);
                self.responses.push(Response::Table { records: empty_records_vec });
                self.number_of_fields = 0;
                self.pending_cmds.remove(0);
                self.pending_cmds_sent -= 1;
                return;
            }
            
            let recnum = pktnum - (2 + self.number_of_fields);
            let mut pos = 0;
            let mut fields: Vec<Field> = Vec::new();        
            
            for x in 0..self.number_of_fields {
                let sz = pktsv.readu8(pos) as usize;
                let data = pktsv.readu8i(pos + 1, sz);
                let field = &mut self.field_headers[x as usize];
                fields.push(match field {
                    &mut FieldHeader::Normal {
                        ref catalog,
                        ref database,
                        ref table,
                        ref origtable,
                        ref name,
                        ref origname,
                        ref charset,
                        ref len,
                        ref stype,
                        ref itype,
                        ref flags,
                        ref decimals
                    } =>
                        match itype {
                            &FieldType::Integer => {
                                Field::i64(String::from_utf8(data).unwrap().parse::<i64>().unwrap())
                            },
                            &FieldType::String => {
                                Field::String(String::from_utf8(data).unwrap())
                            },
                        },
                    &mut FieldHeader::Empty => Field::Unknown,
                });
                pos += sz + 1;  
            }
            
            self.pending_records.push(Record { fields: fields });
        }
        
        // Handle a login failure.
        if pktnum == 2 && self.connstate.is_connected() && op == 0xff {
            self.responses.push(Response::LoginError);
            return;
        }
        
        // Handle a successful login.
        if pktnum == 2 && self.connstate.is_connected() && op == 0x00 {
            self.responses.push(Response::LoginSuccess);
            self.connstate = ConnectionState::Ready;
            return;
        }
        
        // Handle the server greeting.
        if pktnum == 0 && self.connstate.is_connected() && op == 0x0a {
            println!("[mysql] processing welcome packet");
            /* https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake */
            let mut pos: usize = 0;
            let protocol = pktsv.readu8(pos);
            pos += 1;   
            let version = pktsv.readuntil(pos, 0);
            pos += version.len() + 1;
            let threadid = pktsv.readu32le(pos);
            pos += 4;
            let salt0 = pktsv.readuntil(pos, 0);
            pos += salt0.len() + 1;
            let servercap = pktsv.readu16le(pos);
            pos += 2;
            let serverlang = pktsv.readu8(pos);
            pos += 1;
            let serverstatus = pktsv.readu16le(pos);
            pos += 2;
            pos += 13;
            let salt1 = pktsv.readuntil(pos, 0);
            pos += salt1.len() + 1;
            let plugin = pktsv.readuntil(pos, 0);
            pos += plugin.len() + 1;      
                                      
            /* forge our reply */
            let mut reply = SuperVec::new();

            /* https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse */
            /* mimicing protocol dump; lots of little flags here; capability flags */
            pos = 0;
            reply.writeu16le(pos, 0xa605);
            pos += 2;
            reply.writeu16le(pos, 0x000f);
            pos += 2;
            reply.writeu32le(pos, 0x01000000);
            pos += 4;
            /* utf8 */
            reply.writeu8(pos, 0x21);
            pos += 1;
            /* username with null terminator */
            pos = 0x20;
            reply.writeu8i(pos, &self.user);
            pos += self.user.len();
            reply.writeu8(pos, 0);
            pos += 1;
            /* encode password */
            let mut sha1 = sha1::Sha1::new();
            println!("[mysql] doing scramble");
            // get scramble                
            let mut scramble = salt1.clone();                
            
            sha1.reset();
            sha1.update(self.pass.as_slice());
            let hashed = sha1.digest();
            
            sha1.reset();
            sha1.update(hashed.as_slice());                
            let dhashed = sha1.digest();
            
            sha1.reset();
            scramble.append(&mut dhashed.clone());
            sha1.update(scramble.as_slice());
            let mut tfinal = sha1.digest();
            
            println!("[mysql] doing xor");
            for x in 0..tfinal.len() {
                tfinal[x] = tfinal[x] ^ hashed[x % hashed.len()];
            }
            
            println!("[mysql] writing scramble into reply");
            reply.writeu8(pos, tfinal.len() as u8);
            pos += 1;
            reply.writeu8i(pos, &tfinal);
            pos += scramble.len();
            
            /* TODO: fix this up... it is a UTF-8 string that says "mysql_native_password" with a
                     NULL (0x00) at the end..
            */
            reply.writeu8i(pos, &vec![
                0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61,
                0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00
            ]);
            println!("[mysql] sending login request");
            self.send_mysql_packet(1, reply.get_data());
            return;
        }
    }
    
    fn tick_pending_cmd_queue(&mut self) {
        let mut tmp: Vec<PendingCommand> = Vec::new();

        mem::swap(&mut tmp, &mut self.pending_cmds);        
        
        for x in (self.pending_cmds_sent as usize)..tmp.len() {
            match &mut tmp[x] {
                &mut PendingCommand::UseDatabase { ref schema } => {
                    self.send_cmd_use_database(schema.as_slice());             
                },
                &mut PendingCommand::Query { ref querystring } => {
                    self.send_cmd_query(querystring.as_slice());
                },
            }
            self.pending_cmds_sent += 1;
        }
        
        mem::swap(&mut tmp, &mut self.pending_cmds);
    }

    /// Read any data from the network socket, and write any pending data
    /// to the network socket. This will block if `netblock` is set to true
    /// until a network packet arrives. This function returning does not
    /// guarantee that a response is on the response stack.
    ///
    ///
    /// # Why Block with `netblock`
    /// The ability to block provides the calling code with a method to place
    /// the thread into sleep mode if supported by the operating system. This
    /// is the only alternative to polling.
    ///
    /// # Contract
    ///   * no user code side network transmits or receives shall happen until called
    ///   * no network connection establishment shall happen until called
    ///   * network traffic may happen on system side of socket between calls
    pub fn tick(&mut self, netblock: bool) {
        // https://github.com/kmcguire3413/fmrad2db/issues/8
        if self.connstate.is_idle() && !self.socket.is_connected() {
            self.socket.connect(self.remote_ip, self.remote_port);
            return;
        }
        // If there are any commands which have not been sent, then
        // we shall handle that now.
        self.tick_pending_cmd_queue();
        // Handle any socket messages.
        loop {
            let tcpmsg = self.socket.recvex(netblock);
            match tcpmsg {
                TcpSocketMessage::Data(v8) => self.tick_data(v8),
                TcpSocketMessage::Connected => {
                    self.connstate = ConnectionState::Connected;
                    // If there are still pending commands then let us
                    // re-issue those commands.
                    self.pending_cmds_sent = 0;
                    self.tick_pending_cmd_queue();
                },
                TcpSocketMessage::Disconnected => {
                    self.connstate = ConnectionState::Connecting;
                    // Attempt to re-connect to the remote server.
                    self.socket.connect(self.remote_ip, self.remote_port);
                },
                TcpSocketMessage::Connect {dstip, dstport } => panic!("internal error"),
                TcpSocketMessage::Disconnect => panic!("internal error"),
                TcpSocketMessage::Error => {
                    self.connstate = ConnectionState::Connecting;
                    self.socket.connect(self.remote_ip, self.remote_port);
                },
                TcpSocketMessage::EndOfStream => {
                    // Do nothing.
                    // TODO: revise logic here
                }, 
            }
        }
    }
    
    /// This only handles data messages from the socket.
    fn tick_data(&mut self, mut v8: Vec<u8>) {
       println!("[mysql] socket message was data of length {}", v8.len());
        /*
            TODO: think about optimization later if needed
        */
        /*
            Place everything into a contigious buffer. This makes the code logic
            must easier.
        */
        self.buffer.append(&mut v8);

        /*
            Decode the data into MySQL packets. We may only have a partial packet, and
            we shall abort the decoding and place it into a buffer.
        */
        let mut curndx: usize = 0;
        while curndx < self.buffer.len() && self.buffer.len() > 3 {
            println!("[mysql] looking for sub-packet");
            let pktlen = (self.buffer[curndx + 0] as usize) | ((self.buffer[curndx + 1] as usize) << 8) | ((self.buffer[curndx + 2] as usize) << 16);
            let pktnum = self.buffer[curndx + 3];
            if curndx + (pktlen as usize) + 3 + 1 > self.buffer.len() {
                break;
            }
            
            println!("[mysql] pktlen:{} pktnum:{}", pktlen, pktnum);

            /*
                Grab a slice (view) of the buffer. This will help ensure safety that
                we do not under or over-read the buffer, and it is a very cheap operation.
            */
            let pkt: Vec<u8>;
            {
                pkt = (&self.buffer[curndx + 3 + 1..curndx + 3 + 1 + pktlen as usize]).iter().cloned().collect();
            }
            
            self.onpacket(pktnum, &pkt);
            println!("[mysql] got sub-packet of length {}", pkt.len());
            
            curndx += (pktlen as usize) + 3 + 1;
        }

        /*
            Drop anything we have processed and used.
        */
        for x in 0..curndx {
           self.buffer.remove(0);
        }
    }
}