use bytes::{Buf, BufMut};
use num_traits::FromPrimitive;

use crate::io::{BufRead, Error, InPacket, OutPacket, Result};
use crate::net::server_ops;
use crate::time::SystemTime;

pub struct Ping;

impl OutPacket for Ping {
    fn serialize(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.put_u16_le(server_ops::PING);
        p
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
pub enum LoginError {
    IDDeletedOrBlocked = 3,
    IncorrectPassword = 4,
    NotARegisteredID = 5,
    SystemError1 = 6,
    AlreadyLoggedIn = 7,
    SystemError2 = 8,
    SystemError3 = 9,
    CannotProcessSoManyConnections = 10,
    OnlyUsersOlderThan20CanUseThisChannel = 11,
    UnableToLogOnAsMasterAtThisIP = 13,
    WrongGatewayOrPersonalInfoAndWeirdKoreanButton = 14,
    ProcessingRequestWithThatKoreanButton = 15,
    PleaseVerifyYourAccountThroughEmail = 16,
    WrongGatewayOrPersonalInfo = 17,
    PleaseVerifyYourAccountThroughEmail2 = 21,
    LicenseAgreement = 23,
    MapleEuropeNotice = 25,
    TrailVersion = 27,
    Unknown = 0xFF,
}

#[derive(Debug)]
pub enum LoginStatus {
    Success {
        id: u32,
        gender: u8,
        grade: u8,
        sub_grade: u8,
        country_code: u8,
        name: String,
        quiet_ban_reason: u8,
        quiet_ban_lift_date: SystemTime,
        creation: SystemTime,
        request_pin: u8,
        request_pic: u8,
    },
    Failed(String),
    PermanentBan,
    TemporalBan {
        until: SystemTime,
        reason: String,
    },
}

impl InPacket for LoginStatus {
    fn deserialize<B: BufRead>(buf: &mut B) -> Result<Self> {
        let flag = buf.get_i32_le();
        match flag {
            0 => {
                let id = buf.get_u32();
                let gender = buf.get_u8();
                let grade = buf.get_u8();
                let sub_grade = buf.get_u8();
                let country_code = buf.get_u8();
                let name = buf.get_ascii_string();
                let quiet_ban_reason = buf.get_u8();
                let quiet_ban_lift_date = buf.get_time();
                let creation = buf.get_time();
                let request_pin = buf.get_u8();
                let request_pic = buf.get_u8();
                Ok(LoginStatus::Success {
                    id,
                    gender,
                    grade,
                    sub_grade,
                    country_code,
                    name,
                    quiet_ban_reason,
                    quiet_ban_lift_date,
                    creation,
                    request_pin,
                    request_pic,
                })
            }
            2 => {
                let ban_reason = buf.get_u8();
                let until = buf.get_time();
                if ban_reason == 0 {
                    Ok(LoginStatus::PermanentBan)
                } else {
                    let reason: LoginError = FromPrimitive::from_u8(ban_reason).unwrap_or(LoginError::Unknown);
                    Ok(LoginStatus::TemporalBan {
                        until,
                        reason: format!("{:?}", reason),
                    })
                }
            }
            flag => {
                let reason: LoginError = FromPrimitive::from_i32(flag).unwrap_or(LoginError::Unknown);
                Ok(LoginStatus::Failed(format!("{:?}", reason)))
            }
        }
    }
}

impl OutPacket for LoginStatus {
    fn serialize(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.put_u16_le(server_ops::LOGIN_STATUS);

        p
    }
}
