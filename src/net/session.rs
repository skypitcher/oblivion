use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use bytes::{Buf, BufMut, Bytes};

use crate::io::{BufRead, BufWrite, Error, InPacket, OutPacket, Result};

use super::codec::{Decoder, Encoder, MAX_PACKET_SIZE};

#[derive(Debug, Clone)]
pub struct Proto {
    pub version: u16,
    pub patch: String,
    pub send_iv: [u8; 4],
    pub recv_iv: [u8; 4],
    pub locale: u8,
}

impl Proto {
    pub fn remote(&self) -> Self {
        Self {
            version: self.version,
            patch: self.patch.clone(),
            send_iv: self.recv_iv,
            recv_iv: self.send_iv,
            locale: self.locale,
        }
    }
}

impl OutPacket for Proto {
    fn serialize(&self) -> Vec<u8> {
        let packet_len = std::mem::size_of::<u16>() // version
            + (std::mem::size_of::<u16>() + self.patch.len())  // patch
            + self.recv_iv.len()
            + self.send_iv.len()
            + std::mem::size_of::<u8>(); // locale

        let mut out = Vec::new();
        out.put_u16_le(packet_len as u16);
        out.put_u16_le(self.version);
        out.put_ascii_string_with_length(self.patch.as_str());
        out.put_slice(&self.send_iv);
        out.put_slice(&self.recv_iv);
        out.put_u8(self.locale);

        out
    }
}

impl InPacket for Proto {
    fn deserialize<B: BufRead>(buf: &mut B) -> Result<Self> {
        let version = buf.get_u16_le();
        let patch = buf.get_ascii_string();

        let mut send_iv = [0u8; 4];
        buf.copy_to_slice(&mut send_iv);

        let mut recv_iv = [0u8; 4];
        buf.copy_to_slice(&mut recv_iv);

        let locale = buf.get_u8();

        Ok(Proto {
            version,
            patch,
            send_iv,
            recv_iv,
            locale,
        })
    }
}

pub struct Session {
    socket: TcpStream,
    proto: Proto,
    enc: Encoder,
    dec: Decoder,
    buf: [u8; MAX_PACKET_SIZE],
    pos: usize,
}

impl std::fmt::Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.socket)
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Session { socket, proto, enc, dec, buf, pos } => {
                f.debug_struct("Session")
                    .field("socket", socket)
                    .field("proto", proto)
                    .field("enc", enc)
                    .field("dec", dec)
                    .field("pos", pos)
                    .finish()
            }
        }
    }
}

impl Session {
    pub fn connect_server<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let mut socket = TcpStream::connect(addr)?;
        let mut buf = [0u8; MAX_PACKET_SIZE];

        let len = socket.read(&mut buf)?;
        let mut reader = Bytes::copy_from_slice(&buf[..len]);
        let handshake_body_size = reader.get_u16_le() as usize;
        if reader.remaining() != handshake_body_size {
            return Err(Error::from(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Wrong proto size",
            )));
        }

        let proto = Proto::deserialize(&mut reader)?;
        debug!("{:#?}", proto);
        let enc = Encoder::client(proto.version, proto.send_iv);
        let dec = Decoder::client(proto.version, proto.recv_iv);

        socket.set_nonblocking(true)?;

        let pos = len - 2 - handshake_body_size;

        Ok(Session {
            socket,
            proto,
            enc,
            dec,
            buf,
            pos,
        })
    }

    pub fn accept_client(mut socket: TcpStream, proto: Proto) -> std::io::Result<Self> {
        let enc = Encoder::server(proto.version, proto.send_iv);
        let dec = Decoder::server(proto.version, proto.recv_iv);

        socket.set_nonblocking(true)?;
        socket.write_all(proto.serialize().as_ref())?;

        Ok(Session {
            socket,
            proto,
            enc,
            dec,
            buf: [0u8; MAX_PACKET_SIZE],
            pos: 0,
        })
    }

    pub fn send_packet<P: OutPacket>(&mut self, b: P) -> Result<()> {
        self.send(b.serialize().as_slice())
    }

    pub fn send<B: AsRef<[u8]>>(&mut self, b: B) -> Result<()> {
        let encoded_data = self.enc.encode(b.as_ref());
        self.socket
            .write_all(&encoded_data)
            .map_err(|e| Error::from(e))
    }

    pub fn recv(&mut self) -> Result<Option<Bytes>> {
        match self.socket.read(&mut self.buf[self.pos..]) {
            Ok(bytes_read) => {
                if bytes_read > 0 {
                    //debug!("Accept {} bytes", bytes_read);
                    self.pos += bytes_read;
                }
                self.process()
            }
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::WouldBlock => self.process(),
                    _ => Err(Error::from(e))
                }
            }
        }
    }

    fn process(&mut self) -> Result<Option<Bytes>> {
        if self.pos > 0 {
            self.dec.append(&self.buf[..self.pos]);
            self.pos = 0;
        }
        self.dec.decode()
    }
}
