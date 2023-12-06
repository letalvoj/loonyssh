use num_enum::TryFromPrimitive;

use crate::reader::ReadSSH;
pub use ::rustyssh_derive::ReadSSH;
use std::io::{Error, ErrorKind, Read};

#[repr(u32)]
#[derive(Debug, PartialEq, TryFromPrimitive)]
pub enum DisconnectCode {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
}

impl ReadSSH for DisconnectCode {
    fn read_ssh<R: Read>(mut reader: R) -> Result<Self, Error> {
        let code = u32::read_ssh(&mut reader)?;
        DisconnectCode::try_from(code)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid disconnect code"))
    }
}

#[derive(Debug, PartialEq, ReadSSH)]
pub struct Disconnect {
    pub code: DisconnectCode,
    pub description: String,
    pub language: String,
}
