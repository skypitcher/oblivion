use crate::io::{InPacket, BufRead, Result, Error, OutPacket};
use bytes::{Buf, BufMut};
use chrono::prelude::*;

#[derive(Debug)]
pub struct SystemTime {
    year: u16,
    month: u16,
    dayofweek: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

impl From<DateTime<Local>> for SystemTime {
    fn from(t: DateTime<Local>) -> Self {
        Self {
            year: t.year() as u16,
            month: t.month() as u16,
            dayofweek: t.weekday() as u16,
            day: t.day() as u16,
            hour: t.hour() as u16,
            minute: t.minute() as u16,
            second: t.second() as u16,
            milliseconds: t.timestamp_millis() as u16,
        }
    }
}

impl SystemTime {
    pub fn now() -> Self {
        Local::now().into()
    }
}

impl std::fmt::Display for SystemTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}-{} {}:{}:{}.{}", self.year, self.month, self.day, self.hour, self.minute, self.second, self.milliseconds)
    }
}

impl InPacket for SystemTime {
    fn deserialize<B: BufRead>(buf: &mut B) -> Result<Self> {
        let year = buf.get_u16_le();
        let month = buf.get_u16_le();
        let dayofweek = buf.get_u16_le();
        let day = buf.get_u16_le();
        let hour = buf.get_u16_le();
        let minute = buf.get_u16_le();
        let second = buf.get_u16_le();
        let milliseconds = buf.get_u16_le();

        Ok(Self {
            year,
            month,
            dayofweek,
            day,
            hour,
            minute,
            second,
            milliseconds,
        })
    }
}

impl OutPacket for SystemTime {
    fn serialize(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.put_u16_le(self.year);
        p.put_u16_le(self.month);
        p.put_u16_le(self.dayofweek);
        p.put_u16_le(self.day);
        p.put_u16_le(self.hour);
        p.put_u16_le(self.minute);
        p.put_u16_le(self.second);
        p.put_u16_le(self.milliseconds);

        p
    }
}