use num_enum::TryFromPrimitive;

use rustyssh_macros::ReadSSH;

#[derive(ReadSSH)]
pub struct Disconnect {
    pub code: DisconnectCode,
    pub description: String,
    pub language: String,
}

#[repr(u32)]
#[derive(Debug, PartialEq, TryFromPrimitive)]
pub enum DisconnectCode {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
}