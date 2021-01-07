use bytes::Bytes;

use crate::io::{Error, Result};

use super::cipher::MapleAES;
use super::shanda;

pub const MAX_PACKET_SIZE: usize = 64 * 1024;

pub struct Decoder {
    cipher: MapleAES,
    state: DecodeState,
    buf: Vec<u8>,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Decoder { cipher, state, buf } => {
                f.debug_struct("Decoder")
                    .field("cipher", cipher)
                    .field("state", state)
                    .finish()
            }
        }
    }
}

#[derive(Debug)]
enum DecodeState {
    Header,
    Body(usize),
}

impl<'a> Decoder {
    pub fn server(version: u16, remote_iv: [u8; 4]) -> Self {
        let cipher = MapleAES::new(version, remote_iv);
        let state = DecodeState::Header;
        Self {
            cipher,
            state,
            buf: Vec::with_capacity(MAX_PACKET_SIZE),
        }
    }

    pub fn client(version: u16, remote_iv: [u8; 4]) -> Self {
        let cipher = MapleAES::new(0xFFFF - version, remote_iv);
        let state = DecodeState::Header;
        Self {
            cipher,
            state,
            buf: Vec::with_capacity(MAX_PACKET_SIZE),
        }
    }

    pub fn append(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn decode(&mut self) -> Result<Option<Bytes>> {
        match self.state {
            DecodeState::Header => match self.decode_header()? {
                Some(body_size) => {
                    //debug!("Header decoded, body size={}", body_size);
                    self.state = DecodeState::Body(body_size);
                    Ok(None)
                }
                None => Ok(None),
            },
            DecodeState::Body(body_size) => Ok(self.decode_body(body_size)),
        }
    }

    fn decode_header(&mut self) -> Result<Option<usize>> {
        let body_size = {
            if self.buf.len() < 4 {
                return Ok(None);
            }

            if !self.cipher.confirm_header(&self.buf) {
                return decode_failed("Confirm Header failed!");
            }

            decrypt_body_size(&self.buf)
        };

        if body_size < 2 {
            return decode_failed("Body too small");
        }

        Ok(Some(body_size))
    }

    fn decode_body(&mut self, body_size: usize) -> Option<Bytes> {
        if self.buf.len() >= body_size {
            let body = &mut self.buf[4..4 + body_size];
            self.cipher.apply_key_stream(body);
            shanda::decrypt(body);

            let mut data = Vec::with_capacity(body_size);
            data.extend_from_slice(body);
            let remaining = self.buf.len() - body_size - 4;
            if remaining > 0 {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        self.buf.as_ptr().offset(4 + body_size as isize),
                        self.buf.as_mut_ptr(),
                        remaining,
                    );
                }
            }
            self.buf.truncate(remaining);
            //debug!("Body decoded, remaining={}", remaining);

            self.state = DecodeState::Header;
            Some(Bytes::from(data))
        } else {
            None // Need more data
        }
    }
}

fn decrypt_body_size(data: &[u8]) -> usize {
    (((data[0] ^ data[2]) & 0xFFu8) as u32
        | ((((data[1] ^ data[3]) as u16) << 8) & 0xFF00u16) as u32) as usize
}

fn decode_failed<T>(msg: &str) -> Result<T> {
    Err(Error::from(std::io::Error::new(std::io::ErrorKind::InvalidData, msg)))
}
