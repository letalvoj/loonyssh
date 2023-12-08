use std::io::Cursor;

mod api;
mod msg;

use pretty_hex::*;

use crate::api::{ReadSSH, WriteSSH};
use crate::msg::*;


fn main() -> std::io::Result<()> {
    // Create an instance of Disconnect
    let obj = MsgKexInit {
        cookie:[2u8;16],
        kex_algorithms:vec!["kex_algorithms".to_string()],
        server_host_key_algorithms:vec!["server_host_key_algorithms".to_string()],
        encryption_algorithms_client_to_server:vec!["encryption_algorithms_client_to_server".to_string()],
        encryption_algorithms_server_to_client:vec!["encryption_algorithms_server_to_client".to_string()],
        mac_algorithms_client_to_server:vec!["mac_algorithms_client_to_server".to_string()],
        mac_algorithms_server_to_client:vec!["mac_algorithms_server_to_client".to_string()],
        compression_algorithms_client_to_server:vec!["compression_algorithms_client_to_server".to_string()],
        compression_algorithms_server_to_client:vec!["compression_algorithms_server_to_client".to_string()],
        languages_client_to_server:vec!["languages_client_to_server".to_string()],
        languages_server_to_client:vec!["languages_server_to_client".to_string()],
        kex_first_packet_follows:false,
        reserved:32,
    };

    // let obj = Service::ssh__connection;
    
    // Serialize into a byte array
    let mut bytes = Vec::new();
    obj.write_ssh(&mut bytes)?;

    println!("Send: {:?}", obj);
    println!("Byte: {:?}", bytes.hex_dump());

    // Deserialize from the byte array
    let mut cursor = Cursor::new(bytes);
    let deserialized_obj = read_next_message(&mut cursor)?;

    // Check if deserialization is correct
    println!("Rcvd: {:?}", deserialized_obj);
    println!("Mgck: {:?}", MsgDisconnect::MAGIC);

    Ok(())
}
