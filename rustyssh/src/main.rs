mod msg;
mod reader;


impl reader::ReadSSH for msg::DisconnectCode {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        let code = u32::read_ssh(&mut reader)?;
        let disconnect_code = msg::DisconnectCode::try_from(code)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid disconnect code"));

        return disconnect_code;
    }
}

impl reader::ReadSSH for msg::Disconnect {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        let code = msg::DisconnectCode::read_ssh(&mut reader)?;
        let description = String::read_ssh(&mut reader)?;
        let language = String::read_ssh(&mut reader)?;

        Ok(msg::Disconnect { code, description, language })
    }
}

fn main() {
    println!("Hello, world!");
}
