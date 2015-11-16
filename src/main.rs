// ALL RIGHTS RESERVED 2015 
// LEONARD KEVIN MCGUIRE JR. <kmcg3413@gmail.com>
// 242 EAST SKIPPER ROAD
// ECLECTIC, AL 36024

#![feature(vec_push_all)]
#![feature(negate_unsigned)]
#![feature(convert)]
#![feature(core)]
#![feature(core_str_ext)]
#![allow(dead_code)]
#![allow(unused_variables)]
extern crate core;
extern crate pcap;
extern crate byteorder;
extern crate toml;
extern crate ham;

pub mod net;
pub mod common;

use std::sync::{Arc, Mutex, Condvar};
use net::{Net, TcpSocketMessage};
use net::mysql;
use std::fs::File;
use std::env;
use std::collections::HashMap;
use std::str::FromStr;
use std::io::Read;
use core::str::StrExt;

fn create_net_instance() -> Net { 
    let toml = get_test_config();

    let local_ip = match toml.get_string("local_ip") {
        Option::Some(v) => convert_ip32_str_to_bytes(&v),
        Option::None => convert_ip32_str_to_bytes(&String::from_str("127.0.0.1").unwrap()),
    }; 
   
    net::new_net(vec![0xec, 0x55, 0xf9, 0x7a, 0x54, 0x70], local_ip, vec![0x94, 0x10, 0x3e, 0xfd, 0x55, 0x69])
}

// Convert a four part IP address string into a 32-bit big-endian integer.
fn convert_ip32_str_to_bytes(ip: &String) -> u32 {
    let mut ipnumerical: u32 = 0;
    let mut ipdepth: u32 = 4;
    for part in ip.split(".") {
        println!("part:{}", part);
        ipdepth -= 1;
        match part.parse::<u32>() {
            Result::Ok(partval) => {
                ipnumerical = ipnumerical | (partval << (ipdepth * 8));
            },
            Result::Err(err) => (),
        }
    }
    
    ipnumerical
}

fn test_net_tcp_http() {
	/*
		Start the network.
	*/
	let net_instance = create_net_instance();

	/*
		Create a TCP socket and connect to a remote machine.
	*/
	let mut socket = net_instance.new_tcp_socket();

	socket.connect(0x689cf603, 80);

	match unsafe { socket.sys_recv() } {
		TcpSocketMessage::Connected => println!("connected!!"),
		_ => panic!("unexpected message; instead of tcp connected"),
	}

	socket.send("GET / HTTP/1.1\x0d\x0aConnection: keep-alive\x0d\x0aAccept: */*\x0d\x0aHost: kmcg3413.net\x0d\x0a\x0d\x0a".bytes().collect());

   println!("[test_net_tcp_http] waiting on data reply from HTTP server");
   socket.recv();
   println!("[test_net_tcp_http] received data reply from HTTP server");
   
   net_instance.shutdown();
}


fn get_test_config() -> toml::Table {
    let mut config_data = String::new();
    
    File::open("test.toml").and_then(|mut f| {
        f.read_to_string(&mut config_data)
    }).unwrap();
    
    let mut toml_parser = toml::Parser::new(config_data.as_str());        
    let toml = match toml_parser.parse() {
        Option::Some(toml) => toml,
        Option::None => {
            panic!("The TOML config from the file could not be parsed. Is it valid?");
        },
    };
    
    toml    
}

trait tomlTableHelper {
    fn get_string(&self, key: &str) -> Option<String>;
    fn get_integer(&self, key: &str) -> Option<i64>;
}

impl tomlTableHelper for toml::Table {
    fn get_string(&self, key: &str) -> Option<String> {
        match self.get(key) {
            Option::Some(v) => Option::Some(String::from_str(v.as_str().unwrap()).unwrap()),
            Option::None => Option::None,
        }
    }
    
    fn get_integer(&self, key: &str) -> Option<i64> {
        match self.get(key) {
            Option::Some(v) => v.as_integer(),
            Option::None => Option::None,
        }
    }
}

#[test]
fn net_tcp_mysql() {
    test_net_tcp_mysql(get_test_config());
}

fn test_net_tcp_mysql(toml: toml::Table) {
    let mysqlip = match toml.get_string("mysql_ip") {
        Option::Some(v) => convert_ip32_str_to_bytes(&v),
        Option::None => convert_ip32_str_to_bytes(&String::from_str("127.0.0.1").unwrap()),
    }; 
    
    let mysqlport: u16 = match toml.get_integer("mysql_port") {
        Option::Some(v) => v as u16,
        Option::None => 3306u16,
    };
    
    let mysqluser = match toml.get_string("mysql_user") {
        Option::Some(v) => v,
        Option::None => String::from_str("default").unwrap(),
    };
    
    let mysqlpass = match toml.get_string("mysql_pass") {
        Option::Some(v) => v,
        Option::None => String::from_str("default").unwrap(),
    };

    let net = create_net_instance();
    let mut mysqlconn = mysql::MySQLConnection::new_with_ipv4_tcp(
        &net,
        mysqlip,
        mysqlport,
        mysqluser.as_bytes().iter().cloned().collect(),
        mysqlpass.as_bytes().iter().cloned().collect()
    );
    
    println!("created mysql connection instance");

    loop {
        mysqlconn.tick(true);
        let oresp = mysqlconn.pop_response();
        match oresp {
            Option::Some(resp) => match resp {
                mysql::Response::Table { records, headers } => {
                    println!("got table response {}", records.len());
                },
                mysql::Response::Error => (),
                mysql::Response::Success => (),
                mysql::Response::LoginError => {
                    println!("mysql server login failed");
                },
                mysql::Response::LoginSuccess => {
                    println!("mysql server login was good");
                    mysqlconn.use_database("fm2db".as_bytes().to_vec());
                    mysqlconn.query("select * from test".as_bytes().to_vec());
                },
            },
            Option::None => (),
        }
    }
    
    net.recv();
}

fn main() {
    // This forms the buffer with which the radio router sends back
    // transmissions. It may be improved to support meta-data along
    // with the transmissions in order to support more types of data
    // and information.
    let rtrans: Arc<Mutex<Vec<Vec<f32>>>> = Arc::new(Mutex::new(Vec::new()));    
    let rtrans_cloned = rtrans.clone();
    
    // The radio receiver runs as a separate thread at the cost of efficiency
    // in order to isolate it from a suspended wait by this thread due to the
    // processing of network events. It may be determined later that both of
    // these can be combined into a asynchronous single thread solution.
    //thread::spawn(move || {
    //    ham::router(rtrans_cloned);        
    //});
    
    // Here we handle getting the radio transmissions. They are then store them into
    // the MySQL data using our custom embedded ready network stack. These can then
    // be accessed by a web based front-end.
    
    let toml = get_test_config();

    let mysqlip = match toml.get_string("mysql_ip") {
        Option::Some(v) => convert_ip32_str_to_bytes(&v),
        Option::None => convert_ip32_str_to_bytes(&String::from_str("127.0.0.1").unwrap()),
    }; 
    
    let mysqlport: u16 = match toml.get_integer("mysql_port") {
        Option::Some(v) => v as u16,
        Option::None => 3306u16,
    };
    
    let mysqluser = match toml.get_string("mysql_user") {
        Option::Some(v) => v,
        Option::None => String::from_str("default").unwrap(),
    };
    
    let mysqlpass = match toml.get_string("mysql_pass") {
        Option::Some(v) => v,
        Option::None => String::from_str("default").unwrap(),
    };

    let net = create_net_instance();
    let mut mysqlconn = mysql::MySQLConnection::new_with_ipv4_tcp(
        &net,
        mysqlip,
        mysqlport,
        mysqluser.as_bytes().iter().cloned().collect(),
        mysqlpass.as_bytes().iter().cloned().collect()
    );
    
    println!("created mysql connection instance");
    
    {
        let mut rtrans_lock = rtrans.lock().unwrap();
        let mut test: Vec<f32> = Vec::new();
        for x in 0..4000 {
            test.push(x as f32);
        }
        rtrans_lock.push(test);
    }

    loop {
        // Check if there are any transmissions and then grab one
        // of them.
        let mut onetrans: Option<Vec<f32>> = Option::None;        
        {
            let mut rtrans_lock = rtrans.lock().unwrap();
            
            if rtrans_lock.len() > 0 {
                onetrans = Option::Some(rtrans_lock.remove(0));
            }
        }                

        // Let the MySQL connection do any work that needs to be
        // done internally, but _do not_ block here.
        mysqlconn.tick(false);

        // Do we have any transmissions to upload?
        match onetrans {
            Option::Some(v) => {
                // INSERT INTO trans (freq, when, type, data) VALUES
                let mut sqlbuf: Vec<u8> = Vec::with_capacity(v.len() + 1024);

                let xstart = format!(
                    "INSERT INTO trans (freq, type, data) VALUES ({}, 'fmwb', X'",
                    0
                );
                
                let start = xstart.as_bytes();
                
                for x in 0..start.len() {
                    sqlbuf.push(start[x]);
                }
                
                unsafe {
                    let sz = v.len();
                    let ptr = v.as_ptr();
                    let u8buf = Vec::from_raw_parts(ptr as *mut u8, sz * std::mem::size_of::<f32>(), sz * std::mem::size_of::<f32>()); 
                    
                    // From my experiments I see that the MySQL
                    // module for NodeJS sends binary data in 
                    // hex format as a string. This should work
                    // okay for now at least. The problem is that
                    // we are doubling the amount of data that needs
                    // to be sent using hex.

                    let map: [u8; 16] = [
                        '0' as u8, '1' as u8, '2' as u8, '3' as u8, '4' as u8, '5' as u8, '6' as u8,
                        '7' as u8, '8' as u8, '9' as u8, 'a' as u8, 'b' as u8, 'c' as u8, 'd' as u8,
                        'e' as u8, 'f' as u8
                    ];
                
                    for x in 0..u8buf.len() {
                        let hval = u8buf[x];
                        sqlbuf.push(map[(hval >> 4) as usize]);
                        sqlbuf.push(map[(hval & 0x0f) as usize]);
                    }
                    
                    std::mem::forget(u8buf);
                }                
                
                let tail = "')".as_bytes();
                for x in 0..tail.len() {
                    sqlbuf.push(tail[x]);
                }

                let mut usedb: Vec<u8> = Vec::new();
                usedb.push_all("USE fm2db".as_bytes());
                mysqlconn.query(usedb);
                mysqlconn.query(sqlbuf);
            },
            Option::None => (),
        }   
        
        /*
        mysqlconn.tick(true);
        let oresp = mysqlconn.pop_response();
        match oresp {
            Option::Some(resp) => match resp {
                mysql::Response::Table { records, headers } => {
                    println!("got table response {}", records.len());
                },
                mysql::Response::Error => (),
                mysql::Response::Success => (),
                mysql::Response::LoginError => {
                    println!("mysql server login failed");
                },
                mysql::Response::LoginSuccess => {
                    println!("mysql server login was good");
                    mysqlconn.use_database("fm2db".as_bytes().to_vec());
                    mysqlconn.query("select * from test".as_bytes().to_vec());
                },
            },
            Option::None => (),
        }*/
    }
    
    //net.recv();     
}
