// ALL RIGHTS RESERVED 2015 
// LEONARD KEVIN MCGUIRE JR. <kmcg3413@gmail.com>
// 242 EAST SKIPPER ROAD
// ECLECTIC, AL 36024

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
    net::new_net(vec![0xec, 0x55, 0xf9, 0x7a, 0x54, 0x70], 0xc0a80124, vec![0x94, 0x10, 0x3e, 0xfc, 0xc6, 0xf2])
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
    let toml = get_test_config();
    
    test_net_tcp_mysql(toml);
}
