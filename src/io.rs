use bytes::{Buf, BufMut};
use crate::time::SystemTime;

#[derive(Debug)]
pub struct Error {
    message: String,
}

impl<E: ToString> From<E> for Error {
    fn from(e: E) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;


pub trait BufRead: Buf + Sized {
    fn get_ascii_string(&mut self) -> String {
        let str_len = self.get_u16_le() as usize;
        self.get_ascii_string_fixed(str_len)
    }

    fn get_ascii_string_fixed(&mut self, n: usize) -> String {
        if n == 0 {
            String::new()
        } else {
            self.copy_to_bytes(n)
                .into_iter()
                .map(|b| std::char::from_u32(b as u32).unwrap_or('?'))
                .collect::<String>()
        }
    }

    fn get_time(&mut self) -> SystemTime {
        SystemTime::deserialize(self).unwrap()
    }
}

impl<T: Buf + Sized> BufRead for T {}

pub trait BufWrite: BufMut {
    fn put_ascii_string_with_length(&mut self, s: &str) {
        self.put_u16_le(s.len() as u16);
        self.put_ascii_string_without_length(s);
    }

    fn put_ascii_string_without_length(&mut self, s: &str) {
        self.put_slice(s.as_bytes());
    }

    fn put_time_now(&mut self) {
        self.put_slice(SystemTime::now().serialize().as_slice())
    }

    fn put_time(&mut self, st: SystemTime) {
        self.put_slice(st.serialize().as_slice())
    }
}

impl<T: BufMut> BufWrite for T {}

pub trait OutPacket {
    fn serialize(&self) -> Vec<u8>;
}

pub trait InPacket: Sized {
    fn deserialize<B: BufRead>(buf: &mut B) -> Result<Self>;
}
