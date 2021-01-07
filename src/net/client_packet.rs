use bytes::BufMut;

use crate::io::{BufWrite, Error, OutPacket, Result};
use crate::net::client_ops;

pub struct Pong;

impl OutPacket for Pong {
    fn serialize(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.put_u16_le(client_ops::PONG);
        p
    }
}

pub struct ClientStart;

impl OutPacket for ClientStart {
    fn serialize(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.put_u16_le(client_ops::CLIENT_START);
        p
    }
}

pub struct LoginPassword {
    pub name: String,
    pub password: String,
    pub mac1: [u8; 6],
    pub hdd_id: [u8; 4],
    pub mac2: [u8; 6],
}

impl OutPacket for LoginPassword {
    fn serialize(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.put_u16_le(client_ops::LOGIN_PASSWORD);
        p.put_ascii_string_with_length(self.name.as_str());
        p.put_ascii_string_with_length(self.password.as_str());
        p.put_slice(&self.mac1);
        p.put_slice(&self.hdd_id);
        p.put_slice(&self.mac2);                // crc mac2: 00 00 00 00 67 79
        p.put_i32_le(0);                         // game room client Id
        p.put_u8(2);                             // client type
        p.put_u8(0);                             // reversed
        p.put_u8(0);                             // reversed
        p.put_i32_le(0);                         // reversed
        p
    }
}
