#[macro_use]
extern crate log;
extern crate num;
#[macro_use]
extern crate num_derive;
extern crate pretty_env_logger;

use std::convert::TryFrom;

use bytes::{Buf, BufMut};

use crate::io::*;
use crate::net::{client_ops, client_packet, server_ops, server_packet, Session};

mod net;
mod io;
mod time;


fn main() {
    pretty_env_logger::init();

    let remote = "127.0.0.1:8484";

    let mut sess = Session::connect_server(remote).unwrap();
    sess.send_packet(client_packet::ClientStart).unwrap();
    debug!("Start");

    let mut flag = true;

    loop {
        if let Some(mut buf) = sess.recv().unwrap() {
            let opcode = buf.get_u16_le();
            process_packet(&mut sess, opcode, &mut buf).unwrap();
            if !flag {
                let name = "admin";
                let password = name;
                let mac1 = [00, 0xE1, 0xFF, 0xFF, 0xFF, 0xFF];
                let hdd_id = [0x00, 0xE7, 0x89, 0x1B];
                let mac2 = [00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
                login(&mut sess, name, password, mac1, hdd_id, mac2).unwrap();
                debug!("Login");
                flag = true;
            }
        }
    }
}

fn login(sess: &mut Session, name: &str, password: &str, mac1: [u8; 6], hdd_id: [u8; 4], mac2: [u8; 6]) -> Result<()> {
    sess.send_packet(client_packet::LoginPassword {
        name: name.to_owned(),
        password: password.to_owned(),
        mac1,
        hdd_id,
        mac2,
    })
}

fn process_packet<B: BufRead>(sess: &mut Session, opcode: u16, buf: &mut B) -> Result<()> {
    match opcode {
        server_ops::LOGIN_STATUS => on_login_status(sess, buf),
        server_ops::PING => on_ping(sess, buf),
        _ => {
            warn!("Unknown server message OPCODE={}, len={}", opcode, buf.remaining());
            Ok(())
        }
    }
}

fn on_ping<B: BufRead>(sess: &mut Session, buf: &mut B) -> Result<()> {
    debug!("Ping-Pong");
    sess.send_packet(client_packet::Pong)
}

fn on_login_status<B: BufRead>(sess: &mut Session, buf: &mut B) -> Result<()> {
    let result = server_packet::LoginStatus::deserialize(buf)?;
    debug!("{:#?}", result);
    Ok(())
}
