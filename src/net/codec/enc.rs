use super::cipher::MapleAES;
use super::shanda;

#[derive(Debug)]
pub struct Encoder {
    cipher: MapleAES,
}

impl Encoder {
    pub fn server(version: u16, locale_iv: [u8; 4]) -> Self {
        let cipher = MapleAES::new(0xFFFF - version, locale_iv);
        Self { cipher }
    }

    pub fn client(version: u16, locale_iv: [u8; 4]) -> Self {
        let cipher = MapleAES::new(version, locale_iv);
        Self { cipher }
    }

    pub fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        let mut packet = self.cipher.create_header(data.len());
        packet.extend(data);

        shanda::encrypt(&mut packet[4..]);
        self.cipher.apply_key_stream(&mut packet[4..]);

        packet
    }
}
