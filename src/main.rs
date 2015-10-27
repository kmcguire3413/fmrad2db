// ALL RIGHTS RESERVED 2015 
// LEONARD KEVIN MCGUIRE JR. <kmcg3413@gmail.com>
// 242 EAST SKIPPER ROAD
// ECLECTIC, AL 36024

#![feature(negate_unsigned)]
#![feature(convert)]
#![allow(dead_code)]
#![allow(unused_variables)]
extern crate pcap;
extern crate byteorder;

pub mod net;
pub mod common;

use std::sync::{Arc, Mutex, Condvar};
use net::{Net, TcpSocketMessage};
use net::mysql;

fn create_net_instance() -> Net {
    net::new_net(vec![0xec, 0x55, 0xf9, 0x7a, 0x54, 0x70], 0xc0a8010d, vec![0x94, 0x10, 0x3e, 0xfc, 0xc6, 0xf2])
}

#[test]
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

	match socket.sys_recv() {
		TcpSocketMessage::Connected => println!("connected!!"),
		_ => panic!("unexpected message; instead of tcp connected"),
	}

	socket.send("GET / HTTP/1.1\x0d\x0aConnection: keep-alive\x0d\x0aAccept: */*\x0d\x0aHost: kmcg3413.net\x0d\x0a\x0d\x0a".bytes().collect());

   println!("[test_net_tcp_http] waiting on data reply from HTTP server");
   socket.recv();
   println!("[test_net_tcp_http] received data reply from HTTP server");
   
   net_instance.shutdown();
}

fn test_net_tcp_mysql() {
    let net = create_net_instance();
    let mut mysqlconn = mysql::MySQLConnection::new_with_ipv4_tcp(
        &net,
        0x689cf603,
        3306,
        "fm2db".as_bytes().iter().cloned().collect(),
        "Mxn3k2eoo3LsmxSaj3KMnrE3".as_bytes().iter().cloned().collect()
    );
    println!("created mysql connection instance");

    loop {
        mysqlconn.tick(true);
        let oresp = mysqlconn.pop_response();
        match oresp {
            Option::Some(resp) => match resp {
                mysql::Response::Table { records } => {
                    println!("got table response {}", records.len());
                },
                mysql::Response::Error => (),
                mysql::Response::Success => (),
                mysql::Response::LoginError => {
                    println!("mysql server login failed");
                },
                mysql::Response::LoginSuccess => {
                    println!("mysql server login was good");
                },
            },
            Option::None => (),
        }
    }
    
    net.recv();
}

fn main() {
    test_net_tcp_mysql();
}
