use aes::Aes256;
use aes::block_cipher_trait::BlockCipher;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::generic_array::typenum::U16;

const AES256_SECRET_KEY: [u8; 32] = [
    0x13, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00,
    0xB4, 0x00, 0x00, 0x00,
    0x1B, 0x00, 0x00, 0x00,
    0x0F, 0x00, 0x00, 0x00,
    0x33, 0x00, 0x00, 0x00,
    0x52, 0x00, 0x00, 0x00,
];

const SHUFFLE_KEYS: [u8; 256] = [
    0xEC, 0x3F, 0x77, 0xA4, 0x45, 0xD0, 0x71, 0xBF, 0xB7, 0x98, 0x20, 0xFC, 0x4B, 0xE9, 0xB3, 0xE1,
    0x5C, 0x22, 0xF7, 0x0C, 0x44, 0x1B, 0x81, 0xBD, 0x63, 0x8D, 0xD4, 0xC3, 0xF2, 0x10, 0x19, 0xE0,
    0xFB, 0xA1, 0x6E, 0x66, 0xEA, 0xAE, 0xD6, 0xCE, 0x06, 0x18, 0x4E, 0xEB, 0x78, 0x95, 0xDB, 0xBA,
    0xB6, 0x42, 0x7A, 0x2A, 0x83, 0x0B, 0x54, 0x67, 0x6D, 0xE8, 0x65, 0xE7, 0x2F, 0x07, 0xF3, 0xAA,
    0x27, 0x7B, 0x85, 0xB0, 0x26, 0xFD, 0x8B, 0xA9, 0xFA, 0xBE, 0xA8, 0xD7, 0xCB, 0xCC, 0x92, 0xDA,
    0xF9, 0x93, 0x60, 0x2D, 0xDD, 0xD2, 0xA2, 0x9B, 0x39, 0x5F, 0x82, 0x21, 0x4C, 0x69, 0xF8, 0x31,
    0x87, 0xEE, 0x8E, 0xAD, 0x8C, 0x6A, 0xBC, 0xB5, 0x6B, 0x59, 0x13, 0xF1, 0x04, 0x00, 0xF6, 0x5A,
    0x35, 0x79, 0x48, 0x8F, 0x15, 0xCD, 0x97, 0x57, 0x12, 0x3E, 0x37, 0xFF, 0x9D, 0x4F, 0x51, 0xF5,
    0xA3, 0x70, 0xBB, 0x14, 0x75, 0xC2, 0xB8, 0x72, 0xC0, 0xED, 0x7D, 0x68, 0xC9, 0x2E, 0x0D, 0x62,
    0x46, 0x17, 0x11, 0x4D, 0x6C, 0xC4, 0x7E, 0x53, 0xC1, 0x25, 0xC7, 0x9A, 0x1C, 0x88, 0x58, 0x2C,
    0x89, 0xDC, 0x02, 0x64, 0x40, 0x01, 0x5D, 0x38, 0xA5, 0xE2, 0xAF, 0x55, 0xD5, 0xEF, 0x1A, 0x7C,
    0xA7, 0x5B, 0xA6, 0x6F, 0x86, 0x9F, 0x73, 0xE6, 0x0A, 0xDE, 0x2B, 0x99, 0x4A, 0x47, 0x9C, 0xDF,
    0x09, 0x76, 0x9E, 0x30, 0x0E, 0xE4, 0xB2, 0x94, 0xA0, 0x3B, 0x34, 0x1D, 0x28, 0x0F, 0x36, 0xE3,
    0x23, 0xB4, 0x03, 0xD8, 0x90, 0xC8, 0x3C, 0xFE, 0x5E, 0x32, 0x24, 0x50, 0x1F, 0x3A, 0x43, 0x8A,
    0x96, 0x41, 0x74, 0xAC, 0x52, 0x33, 0xF0, 0xD9, 0x29, 0x80, 0xB1, 0x16, 0xD3, 0xAB, 0x91, 0xB9,
    0x84, 0x7F, 0x61, 0x1E, 0xCF, 0xC5, 0xD1, 0x56, 0x3D, 0xCA, 0xF4, 0x05, 0xC6, 0xE5, 0x08, 0x49,
];

pub struct MapleAES {
    build: u16,
    iv: [u8; 4],
    aes_ecb: Aes256,
}

impl std::fmt::Debug for MapleAES {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MapleAES { build, iv, aes_ecb } => {
                f.debug_struct("MapleAES")
                    .field("build", build)
                    .field("iv", iv)
                    .finish()
            }
        }
    }
}

impl MapleAES {
    pub fn new(version: u16, iv: [u8; 4]) -> MapleAES {
        let build = ((version >> 8) & 0xFF) | ((version << 8) & 0xFF00);
        let aes_ecb = Aes256::new(GenericArray::from_slice(&AES256_SECRET_KEY));
        MapleAES { build, iv, aes_ecb }
    }

    pub fn apply_key_stream(&mut self, data: &mut [u8]) {
        let mut remaining: usize = data.len();
        let mut llength: usize = 0x5B0;
        let mut start: usize = 0;
        while remaining > 0 {
            let mut block = self.make_init_block();
            if remaining < llength {
                llength = remaining;
            }

            for x in start..start + llength {
                let idx = x - start;
                if idx % 16 == 0 {
                    self.aes_ecb.encrypt_block(&mut block);
                }
                data[x] ^= block[idx % 16];
            }

            start += llength;
            remaining -= llength;
            llength = 0x5B4;
        }
        self.update();
    }

    pub fn create_header(&self, packet_len: usize) -> Vec<u8> {
        let length = packet_len as u32;
        let mut header = Vec::with_capacity(6);

        let mut iiv = (self.iv[3] as u32) & 0xFF;
        iiv |= (self.iv[2] as u32).wrapping_shl(8) & 0xFF00;

        iiv ^= self.build as u32;
        let m_length = (length.wrapping_shl(8) & 0xFF00) | length.wrapping_shr(8);
        let xored_iv = iiv ^ m_length;

        let a = (iiv.wrapping_shr(8) & 0xFF) as u8;
        let b = (iiv & 0xFF) as u8;
        let c = (xored_iv.wrapping_shr(8) & 0xFF) as u8;
        let d = (xored_iv & 0xFF) as u8;

        header.push(a);
        header.push(b);
        header.push(c);
        header.push(d);

        header
    }

    pub fn confirm_header(&self, packet: &[u8]) -> bool {
        return ((packet[0] ^ self.iv[2]) & 0xFF) == ((self.build >> 8) & 0xFF) as u8
            && ((packet[1] ^ self.iv[3]) & 0xFF) == (self.build & 0xFF) as u8;
    }

    fn make_init_block(&self) -> GenericArray<u8, U16> {
        let mut block = GenericArray::from([0u8; 16]);
        for i in (0..16).step_by(4) {
            unsafe {
                std::ptr::copy_nonoverlapping(self.iv.as_ptr(), block.as_mut_ptr().offset(i), 4);
            }
        }
        block
    }

    fn update(&mut self) {
        let mut init_iv: [u8; 4] = [0xF2, 0x53, 0x50, 0xC6];
        for i in 0..4 {
            shuffle(self.iv[i], &mut init_iv);
        }
        self.iv = init_iv;
    }
}

fn shuffle(input: u8, init_iv: &mut [u8; 4]) {
    let mut elina = init_iv[1];
    let anna = input;
    let mut moritz = SHUFFLE_KEYS[(elina & 0xFF) as usize];

    moritz = moritz.wrapping_sub(input);
    init_iv[0] = init_iv[0].wrapping_add(moritz);
    moritz = init_iv[2];
    moritz ^= SHUFFLE_KEYS[(anna & 0xFF) as usize];
    elina = elina.wrapping_sub(moritz & 0xFF);
    init_iv[1] = elina;

    elina = init_iv[3];
    moritz = elina;
    elina = elina.wrapping_sub(init_iv[0]);
    moritz = SHUFFLE_KEYS[(moritz & 0xFF) as usize];
    moritz = moritz.wrapping_add(input);
    moritz ^= init_iv[2];
    init_iv[2] = moritz;

    elina = elina.wrapping_add(SHUFFLE_KEYS[(anna & 0xFF) as usize]);
    init_iv[3] = elina;

    let mut merry = (init_iv[0] & 0xFF) as u32;
    merry |= (init_iv[1] as u32).wrapping_shl(8) & 0xFF00;
    merry |= (init_iv[2] as u32).wrapping_shl(16) & 0xFF0000;
    merry |= (init_iv[3] as u32).wrapping_shl(24) & 0xFF000000;

    let mut ret_value = merry;
    ret_value = ret_value.wrapping_shr(0x1d);
    merry = merry.wrapping_shl(3);
    ret_value |= merry;

    init_iv[0] = (ret_value & 0xFF) as u8;
    init_iv[1] = (ret_value.wrapping_shr(8) & 0xFF) as u8;
    init_iv[2] = (ret_value.wrapping_shr(16) & 0xFF) as u8;
    init_iv[3] = (ret_value.wrapping_shr(24) & 0xFF) as u8;
}

#[cfg(test)]
mod test_cipher {
    use super::MapleAES;

    #[test]
    fn test_apply_key_stream() {
        let mut cipher = MapleAES::new(83, [0, 1, 2, 3]);
        let mut data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        cipher.apply_key_stream(&mut data);
        assert_eq!(
            data,
            [0xA2, 0xFD, 0xEC, 0x15, 0x38, 0x22, 0xC8, 0x0B, 0x8F, 0xDB]
        );
    }

    #[test]
    fn test_update() {
        let mut cipher = MapleAES::new(83, [0, 1, 2, 3]);
        let mut data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        cipher.apply_key_stream(&mut data);
        cipher.apply_key_stream(&mut data);
        cipher.apply_key_stream(&mut data);
        cipher.apply_key_stream(&mut data);
        cipher.apply_key_stream(&mut data);
        assert_eq!(
            data,
            [0xE2, 0x3E, 0xA9, 0x52, 0x13, 0xCD, 0xD0, 0x4C, 0x86, 0x07]
        );
    }

    #[test]
    fn test_header() {
        let cipher = MapleAES::new(83, [0, 1, 2, 3]);
        let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let header = cipher.create_header(data.len());
        assert_eq!(header, [0x51, 0x03, 0x5B, 0x03]);
        assert!(cipher.confirm_header(&header));
    }
}
