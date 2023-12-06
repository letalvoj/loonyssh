use std::io::Cursor;

mod api;
mod msg;

use crate::api::{ReadSSH, WriteSSH};
use crate::msg::{SSHMessage, Disconnect, DisconnectCode, read_next_message};

fn main() -> std::io::Result<()> {
    // Create an instance of Disconnect
    let disconnect = Disconnect {
        code: DisconnectCode::HostNotAllowedToConnect,
        description: "Example Description".to_string(),
        language: "en-US".to_string(),
    };

    // Serialize into a byte array
    let mut bytes = Vec::new();
    disconnect.write_ssh(&mut bytes)?;

    // Deserialize from the byte array
    let mut cursor = Cursor::new(bytes);
    let deserialized_disconnect = read_next_message(&mut cursor)?;

    // Check if deserialization is correct
    println!("Send: {:?}", disconnect);
    println!("Rcvd: {:?}", deserialized_disconnect);
    println!("Mgck: {:?}", Disconnect::MAGIC);

    Ok(())
}
