use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use byteorder::{BigEndian, ReadBytesExt};

// These should be in your src/lib.rs or similar
// Making them public to be accessible from the binary crate.
pub mod api;
pub mod msg;

use crate::api::WriteSSH;
use crate::msg::*;

// TODO(jules): Implement the server to a point where it anounces simple cyphers, passes kex, accepts password auth, verifies that the credentials are admin:password and responds with
// If the test successfully passes, turn this TODO into a method comment, outlining what the code is finally doing, but do not drop it.
//
// This project has deps supporting the following KEX settup:
//
// KEX: ecdh-sha2-nistp256
// Host Key: ssh-ed25519
// Cipher: aes128-ctr
// The 'ctr' crate provides the Counter (CTR) mode of operation for block ciphers.
// MAC: hmac-sha2-256

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:2222";
    let listener = TcpListener::bind(addr).await?;

    // Spawn the server task to handle one incoming connection.
    let server_handle = tokio::spawn(async move {
        let (mut socket, _addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("[Server] Failed to accept connection: {}", e);
                return;
            }
        };

        println!("[Server] Client connected. Starting SSH handshake...");

        // 1. Version Exchange
        let mut buffer = vec![0; 256];
        let n = socket
            .read(&mut buffer)
            .await
            .expect("Failed to read client version");
        buffer.truncate(n);

        let client_version = String::from_utf8_lossy(&buffer).trim().to_string();
        println!("[Server] Received client version: {}", client_version);

        let server_version = "SSH-2.0-RustSSH_0.1\r\n";
        socket
            .write_all(server_version.as_bytes())
            .await
            .expect("Failed to send server version");
        println!("[Server] Sent server version.");

        // 2. Message Loop with Packet Framing
        let (mut rd, mut wr) = socket.into_split();
        let mut read_buffer: Vec<u8> = Vec::new();

        loop {
            // Read more data from the socket into our buffer.
            let mut temp_buf = [0; 1024];
            match timeout(Duration::from_secs(5), rd.read(&mut temp_buf)).await {
                Err(_) => {
                    println!("\n[Server] Timeout. Closing connection.");
                    break;
                }
                Ok(Ok(0)) => {
                    println!("\n[Server] Client closed the connection.");
                    break;
                }
                Ok(Ok(n)) => {
                    read_buffer.extend_from_slice(&temp_buf[..n]);
                }
                Ok(Err(e)) => {
                    eprintln!("\n[Server] Error reading from socket: {}", e);
                    break;
                }
            };

            // --- SSH Packet Decoding Logic ---
            // A packet needs at least 5 bytes for length and padding fields.
            if read_buffer.len() < 5 {
                continue; // Not enough data for a header, need to read more.
            }

            let mut header_cursor = std::io::Cursor::new(&read_buffer[..4]);
            // Disambiguate the call to read_u32 to use the synchronous version from ReadBytesExt.
            let packet_length = ReadBytesExt::read_u32::<BigEndian>(&mut header_cursor).unwrap() as usize;
            let padding_length = read_buffer[4] as usize;
            
            let total_packet_size = 4 + packet_length; // total size on the wire

            if read_buffer.len() < total_packet_size {
                 continue; // We don't have the full packet yet, read more.
            }

            // We have a full packet, let's extract the payload.
            let payload_end = 4 + packet_length - padding_length;
            let payload = &read_buffer[5..payload_end];

            let mut payload_cursor = std::io::Cursor::new(payload);
            match read_next_message(&mut payload_cursor) {
                Ok(msg) => {
                    println!("[Server] Parsed message: {:?}", msg);

                    if let SSHMsg::KexInit(_client_kex_init) = msg {
                        println!("[Server] Responding to KexInit...");
                        let server_kex_init = MsgKexInit {
                            cookie: [1; 16], // Should be random
                            kex_algorithms: vec!["ecdh-sha2-nistp256".to_string()],
                            server_host_key_algorithms: vec!["ssh-ed25519".to_string()],
                            encryption_algorithms_client_to_server: vec!["aes128-ctr".to_string()],
                            encryption_algorithms_server_to_client: vec!["aes128-ctr".to_string()],
                            mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_string()],
                            mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_string()],
                            compression_algorithms_client_to_server: vec!["none".to_string()],
                            compression_algorithms_server_to_client: vec!["none".to_string()],
                            languages_client_to_server: Vec::new(),
                            languages_server_to_client: Vec::new(),
                            kex_first_packet_follows: false,
                            reserved: 0,
                        };

                        // --- SSH Packet Encoding Logic ---
                        let mut payload_buf = Vec::new();
                        MsgKexInit::MAGIC.write_ssh(&mut payload_buf).unwrap();
                        server_kex_init.write_ssh(&mut payload_buf).unwrap();

                        // The total length of (padding_length + payload) must be a multiple of the cipher block size (8 for "none")
                        let block_size = 8;
                        let mut padding_len = block_size - (1 + payload_buf.len()) % block_size;
                        if padding_len < 4 { padding_len += block_size; }

                        let packet_len = 1 + payload_buf.len() + padding_len;

                        let mut final_packet = Vec::new();
                        final_packet.extend_from_slice(&(packet_len as u32).to_be_bytes());
                        final_packet.push(padding_len as u8);
                        final_packet.extend_from_slice(&payload_buf);
                        final_packet.extend_from_slice(&vec![0; padding_len]); // Use zero padding for now

                        if let Err(e) = wr.write_all(&final_packet).await {
                            eprintln!("[Server] Failed to write response: {}", e);
                            break;
                        }
                        println!("[Server] Sent KexInit reply packet.");
                    }

                    // Remove the processed packet from the buffer
                    read_buffer.drain(..total_packet_size);
                }
                Err(e) => {
                    eprintln!("[Server] Payload parse error: {}. Dropping connection.", e);
                    break;
                }
            }
        }
    });

    // Short delay to ensure the server is ready.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Spawn the local `ssh` client.
    // We use `sshpass` to provide the password non-interactively for testing purposes.
    // TODO: Install sudo apt-get install sshpass
    // This avoids the interactive password prompt from the `ssh` client.
    println!("[Client] Starting SSH subprocess with sshpass...");
    let mut child = Command::new("sshpass")
        .arg("-p")
        .arg("password") // This is the password we expect the server to verify.
        .arg("ssh")
        .arg("admin@localhost")
        .arg("-p")
        .arg("2222")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-T")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;


    // Wait for the server or the client process to finish.
    tokio::select! {
        res = server_handle => println!("[Main] Server task finished with result: {:?}", res),
        status = child.wait() => println!("[Main] SSH client process exited with status: {:?}", status),
    }

    Ok(())
}
