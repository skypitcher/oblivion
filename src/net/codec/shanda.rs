#[inline]
fn roll_left(value: u8, count: u32) -> u8 {
    let mut tmp = (value & 0xFF) as u32;
    tmp = tmp.wrapping_shl(count % 8);
    return ((tmp & 0xFF) | tmp.wrapping_shr(8)) as u8;
}

#[inline]
fn roll_right(value: u8, count: u32) -> u8 {
    let mut tmp = (value & 0xFF) as u32;
    tmp = tmp.wrapping_shl(8).wrapping_shr(count % 8);
    return ((tmp & 0xFF) | tmp.wrapping_shr(8)) as u8;
}

pub fn encrypt(data: &mut [u8]) {
    for j in 0..6 {
        let mut remember = 0u8;
        let mut data_length = (data.len() & 0xFF) as u8;
        if j % 2 == 0 {
            for i in 0..data.len() {
                let mut cur = data[i];
                cur = roll_left(cur, 3);
                cur = cur.wrapping_add(data_length);
                cur ^= remember;
                remember = cur;
                cur = roll_right(cur, (data_length & 0xFF) as u32);
                cur = (!cur) & 0xFF;
                cur = cur.wrapping_add(0x48);
                data_length = data_length.wrapping_sub(1);
                data[i] = cur;
            }
        } else {
            for i in (0..data.len()).rev() {
                let mut cur = data[i];
                cur = roll_left(cur, 4);
                cur = cur.wrapping_add(data_length);
                cur ^= remember;
                remember = cur;
                cur ^= 0x13;
                cur = roll_right(cur, 3);
                data_length = data_length.wrapping_sub(1);
                data[i] = cur;
            }
        }
    }
}

pub fn decrypt(data: &mut [u8]) {
    for j in 1..=6 {
        let mut remember = 0u8;
        let mut data_length = (data.len() & 0xFF) as u8;
        let mut next_remember: u8;
        if j % 2 == 0 {
            for i in 0..data.len() {
                let mut cur = data[i];
                cur = cur.wrapping_sub(0x48);
                cur = (!cur) & 0xFF;
                cur = roll_left(cur, (data_length & 0xFF) as u32);
                next_remember = cur;
                cur ^= remember;
                remember = next_remember;
                cur = cur.wrapping_sub(data_length);
                cur = roll_right(cur, 3);
                data[i] = cur;
                data_length = data_length.wrapping_sub(1);
            }
        } else {
            for i in (0..data.len()).rev() {
                let mut cur = data[i];
                cur = roll_left(cur, 3);
                cur ^= 0x13;
                next_remember = cur;
                cur ^= remember;
                remember = next_remember;
                cur = cur.wrapping_sub(data_length);
                cur = roll_right(cur, 4);
                data[i] = cur;
                data_length = data_length.wrapping_sub(1);
            }
        }
    }
}

#[test]
fn test_shanda_encrypt() {
    let mut data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
    encrypt(&mut data);
    assert_eq!(data, [0xA0, 0xAA, 0x14, 0x54, 0xEA, 0xA7, 0x75, 0x15, 0xCF, 0x0F]);
}

#[test]
fn test_shanda_decrypt() {
    let mut data = [0xA0, 0xAA, 0x14, 0x54, 0xEA, 0xA7, 0x75, 0x15, 0xCF, 0x0F];

    decrypt(&mut data);
    assert_eq!(data, [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
}

