use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use byteorder::{BigEndian, ReadBytesExt};

pub mod api;
pub mod msg;

use crate::api::{ReadSSH, WriteSSH};
use crate::msg::*;

use ed25519_dalek::{Signer, SigningKey};
use p256::ecdh::EphemeralSecret;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Formats a byte slice into a Python-style `repr()` string for readable logging.
fn format_bytes_as_repr(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2 + 2);
    s.push('"');
    for &byte in bytes {
        match byte {
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            32..=126 => s.push(byte as char),
            _ => s.push_str(&format!("\\x{:02x}", byte)),
        }
    }
    s.push('"');
    s
}


// --- PLACEHOLDER: Crypto Layer Stubs ---
// This struct and the following functions are stubs to show where the real
// crypto implementation needs to go. They currently perform no encryption.

struct CryptoState {
    // These would be real cipher instances, e.g., Ctr128BE<Aes128>
    // and Hmac<Sha256>.
    // For now, they are just placeholders.
    #[allow(dead_code)]
    is_active: bool,
}

/// Placeholder for decrypting and verifying a packet.
/// A real implementation would decrypt `encrypted_data` and verify the MAC.
fn decrypt_and_verify(
    _crypto: &mut CryptoState,
    _sequence_num: u32,
    encrypted_data: &[u8],
) -> Result<Vec<u8>, std::io::Error> {
    println!("[Server] !! STUB: Attempting to decrypt packet. In a real server, this would decrypt. Passing through for now.");
    // A real implementation would return an error if the MAC was invalid.
    Ok(encrypted_data.to_vec())
}

/// Placeholder for encrypting and MAC-ing a packet.
/// A real implementation would encrypt `plaintext_packet` and append a MAC.
fn encrypt_and_mac(
    _crypto: &mut CryptoState,
    _sequence_num: u32,
    plaintext_packet: &[u8],
) -> Result<Vec<u8>, std::io::Error> {
     println!("[Server] !! STUB: Attempting to encrypt packet. In a real server, this would encrypt. Passing through for now.");
    Ok(plaintext_packet.to_vec())
}
// --- END PLACEHOLDER ---


fn build_packet(payload: &[u8]) -> Vec<u8> {
    let block_size = 8; // For plaintext. Would be 16 for AES.

    let unpadded_len = 4 + 1 + payload.len();
    let remainder = unpadded_len % block_size;
    let mut padding_len = if remainder == 0 { 0 } else { block_size - remainder };
    if padding_len < 4 {
        padding_len += block_size;
    }

    let packet_length_val = 1 + payload.len() + padding_len;
    let mut packet = Vec::with_capacity(4 + packet_length_val);
    packet.extend_from_slice(&(packet_length_val as u32).to_be_bytes());
    packet.push(padding_len as u8);
    packet.extend_from_slice(payload);
    packet.extend_from_slice(&vec![0u8; padding_len]);

    packet
}

async fn send_packet<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &(impl WriteSSH + SSHMagic + std::fmt::Debug),
    server_crypto: &mut Option<CryptoState>
) -> std::io::Result<()> {
    let mut payload_buf = Vec::new();
    msg.write_ssh(&mut payload_buf)?;
    
    println!("\n[Server] >> Preparing to send message: {:?}", msg);
    println!("[Server] -> Serialized payload ({} bytes): {}", payload_buf.len(), format_bytes_as_repr(&payload_buf));

    let packet_to_send = if let Some(ref mut crypto) = server_crypto {
        // After NewKeys, packets must be encrypted.
        let framed_packet = build_packet(&payload_buf);
        // The real implementation would pass a sequence number here.
        encrypt_and_mac(crypto, 0, &framed_packet)?
    } else {
        // Before NewKeys, packets are plaintext.
        build_packet(&payload_buf)
    };

    println!("[Server] -> Full packet to be sent ({} bytes): {}", packet_to_send.len(), format_bytes_as_repr(&packet_to_send));
    writer.write_all(&packet_to_send).await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:2222";
    let listener = TcpListener::bind(addr).await?;
    let host_key = SigningKey::generate(&mut OsRng);
    let host_key = Arc::new(host_key);

    let server_handle = tokio::spawn(async move {
        let (mut socket, _addr) = listener.accept().await.expect("Failed to accept");
        println!("[Server] Client connected. Starting SSH handshake...");

        // 1. Version Exchange
        let mut buffer = vec![0; 256];
        let n = socket.read(&mut buffer).await.expect("Failed to read version");
        buffer.truncate(n);
        let mut len = buffer.len();
        while len > 0 && (buffer[len - 1] == b'\n' || buffer[len - 1] == b'\r') { len -= 1; }
        let client_version_bytes = buffer[..len].to_vec();
        let client_version = String::from_utf8_lossy(&client_version_bytes);
        println!("[Server] Received client version: {}", client_version);

        let server_version = "SSH-2.0-RustSSH_0.1\r\n";
        socket.write_all(server_version.as_bytes()).await.unwrap();
        println!("[Server] Sent server version.");

        let (mut rd, mut wr) = socket.into_split();
        let mut read_buffer: Vec<u8> = Vec::new();
        
        // KEX State
        let server_ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let server_ephemeral_pk = server_ephemeral_secret.public_key();
        let mut client_kex_init_payload: Option<Vec<u8>> = None;
        let mut server_kex_init_payload: Option<Vec<u8>> = None;
        let mut authenticated = false;

        // Crypto State
        let mut client_crypto: Option<CryptoState> = None;
        let mut server_crypto: Option<CryptoState> = None;

        loop {
            let mut temp_buf = [0; 1024];
            match timeout(Duration::from_secs(10), rd.read(&mut temp_buf)).await {
                Err(_) => { println!("\n[Server] Timeout."); break; }
                Ok(Ok(0)) => { println!("\n[Server] Client disconnected."); break; }
                Ok(Ok(n)) => {
                    println!("\n[Server] << Read {} bytes from socket: {}", n, format_bytes_as_repr(&temp_buf[..n]));
                    read_buffer.extend_from_slice(&temp_buf[..n]);
                    println!("[Server] -- Read buffer now has {} bytes.", read_buffer.len());
                },
                Ok(Err(e)) => { eprintln!("\n[Server] Read error: {}", e); break; }
            };

            'packet_loop: loop {
                let packet_data = if let Some(ref mut crypto) = client_crypto {
                    // BUG FIX: After NEWKEYS, the stream is encrypted.
                    // A real implementation needs to find packet boundaries in the encrypted stream,
                    // which is tricky. For AES, block size is 16. We'd read 16 bytes, decrypt,
                    // get the length, then read and decrypt the rest.
                    // Here we just STUB the decryption of the whole buffer.
                    if read_buffer.is_empty() { break 'packet_loop; }
                    let decrypted_buffer = decrypt_and_verify(crypto, 0, &read_buffer).unwrap();
                    read_buffer = decrypted_buffer; // Replace buffer with decrypted data
                    // Now proceed with plaintext logic on the decrypted buffer
                    // This is a simplification; a real stream parser is needed.
                    if read_buffer.len() < 5 { break 'packet_loop; }
                    let packet_length = ReadBytesExt::read_u32::<BigEndian>(&mut &read_buffer[..4]).unwrap() as usize;
                    let total_packet_size = 4 + packet_length;
                    if read_buffer.len() < total_packet_size { break 'packet_loop; }
                    read_buffer.drain(..total_packet_size).collect::<Vec<u8>>()

                } else {
                    // Before NEWKEYS, stream is plaintext
                    if read_buffer.len() < 5 { break 'packet_loop; }
                    let packet_length = ReadBytesExt::read_u32::<BigEndian>(&mut &read_buffer[..4]).unwrap() as usize;
                    let total_packet_size = 4 + packet_length;
                    if read_buffer.len() < total_packet_size { break 'packet_loop; }
                    read_buffer.drain(..total_packet_size).collect::<Vec<u8>>()
                };
                
                println!("[Server] -- Processing packet ({} bytes total): {}", packet_data.len(), format_bytes_as_repr(&packet_data));

                let padding_length = packet_data[4] as usize;
                let payload = &packet_data[5..(packet_data.len() - padding_length)];
                
                println!("[Server] -- Extracted payload ({} bytes): {}", payload.len(), format_bytes_as_repr(payload));
                let raw_packet_payload = payload.to_vec();

                let mut cursor = std::io::Cursor::new(payload);
                match read_next_message(&mut cursor) {
                    Ok(msg) => {
                        println!("[Server] -- Parsed message: {:?}", msg);
                        match msg {
                            SSHMsg::KexInit(_) => {
                                client_kex_init_payload = Some(raw_packet_payload);
                                let kex_init = MsgKexInit {
                                    cookie: [0; 16],
                                    kex_algorithms: vec!["ecdh-sha2-nistp256".into()],
                                    server_host_key_algorithms: vec!["ssh-ed25519".into()],
                                    encryption_algorithms_client_to_server: vec!["aes128-ctr".into()],
                                    encryption_algorithms_server_to_client: vec!["aes128-ctr".into()],
                                    mac_algorithms_client_to_server: vec!["hmac-sha2-256".into()],
                                    mac_algorithms_server_to_client: vec!["hmac-sha2-256".into()],
                                    compression_algorithms_client_to_server: vec!["none".into()],
                                    compression_algorithms_server_to_client: vec!["none".into()],
                                    languages_client_to_server: vec![],
                                    languages_server_to_client: vec![],
                                    kex_first_packet_follows: false,
                                    reserved: 0,
                                };
                                let mut s_payload = Vec::new();
                                kex_init.write_ssh(&mut s_payload).unwrap();
                                server_kex_init_payload = Some(s_payload);
                                send_packet(&mut wr, &kex_init, &mut server_crypto).await.unwrap();
                            }
                            SSHMsg::KexECDHInit(req) => {
                                let client_pk = p256::PublicKey::from_sec1_bytes(&req.q_c).unwrap();
                                let shared = server_ephemeral_secret.diffie_hellman(&client_pk);
                                let mut k = shared.raw_secret_bytes().to_vec();
                                if k.get(0).map_or(false, |&b| b & 0x80 != 0) { k.insert(0, 0); }

                                let mut k_s = Vec::new();
                                "ssh-ed25519".to_string().write_ssh(&mut k_s).unwrap();
                                host_key.verifying_key().to_bytes().to_vec().write_ssh(&mut k_s).unwrap();

                                let mut h = Sha256::new();
                                client_version_bytes.write_ssh(&mut h).unwrap();
                                server_version.trim().as_bytes().to_vec().write_ssh(&mut h).unwrap();
                                client_kex_init_payload.as_ref().unwrap().write_ssh(&mut h).unwrap();
                                server_kex_init_payload.as_ref().unwrap().write_ssh(&mut h).unwrap();
                                k_s.write_ssh(&mut h).unwrap();
                                req.q_c.write_ssh(&mut h).unwrap();
                                server_ephemeral_pk.to_sec1_bytes().to_vec().write_ssh(&mut h).unwrap();
                                k.write_ssh(&mut h).unwrap();
                                let exchange_hash = h.finalize();

                                let signature = host_key.sign(&exchange_hash);
                                let mut sig_blob = Vec::new();
                                "ssh-ed25519".to_string().write_ssh(&mut sig_blob).unwrap();
                                signature.to_bytes().to_vec().write_ssh(&mut sig_blob).unwrap();
                                
                                let reply = MsgKexECDHReply { k_s, q_s: server_ephemeral_pk.to_sec1_bytes().to_vec(), signature: sig_blob, };
                                send_packet(&mut wr, &reply, &mut server_crypto).await.unwrap();
                            }
                            SSHMsg::NewKeys(_) => {
                                // Client sent NewKeys. We must now use crypto for incoming packets.
                                // Key derivation would happen here.
                                println!("[Server] !! Activating crypto for client->server messages.");
                                client_crypto = Some(CryptoState { is_active: true });

                                // Send our NewKeys message.
                                send_packet(&mut wr, &MsgNewKeys {}, &mut server_crypto).await.unwrap();

                                // After sending our NewKeys, we must use crypto for outgoing packets.
                                println!("[Server] !! Activating crypto for server->client messages.");
                                server_crypto = Some(CryptoState { is_active: true });
                            }
                            SSHMsg::ServiceRequest(req) => {
                                if req.service_name == "ssh-userauth" {
                                    let accept = MsgServiceAccept { service_name: "ssh-userauth".into() };
                                    send_packet(&mut wr, &accept, &mut server_crypto).await.unwrap();
                                }
                            }
                            SSHMsg::UserauthRequest(req) => {
                                match req.method_name.as_str() {
                                    "none" => {
                                        let failure = MsgUserauthFailure {
                                            authentications_that_can_continue: vec!["password".into()],
                                            partial_success: false,
                                        };
                                        send_packet(&mut wr, &failure, &mut server_crypto).await.unwrap();
                                    }
                                    "password" => {
                                        let _has_old_pw: bool = ReadSSH::read_ssh(&mut cursor).unwrap();
                                        let password_str: String = ReadSSH::read_ssh(&mut cursor).unwrap();
                                        
                                        if req.user_name == "admin" && password_str == "password" {
                                            send_packet(&mut wr, &MsgUserauthSuccess {}, &mut server_crypto).await.unwrap();
                                            authenticated = true;
                                        } else {
                                            let failure = MsgUserauthFailure {
                                                authentications_that_can_continue: vec!["password".into()],
                                                partial_success: false,
                                            };
                                            send_packet(&mut wr, &failure, &mut server_crypto).await.unwrap();
                                        }
                                    }
                                    _ => break 'packet_loop,
                                }
                            }
                            _ => {
                                if authenticated {
                                    println!("[Server] Authenticated. Closing connection gracefully.");
                                    break 'packet_loop;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Server] Payload parse error: {}. Dropping.", e);
                        break 'packet_loop;
                    }
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    println!("[Client] Starting SSH subprocess with sshpass...");
    let mut child = Command::new("sshpass")
        .arg("-p")
        .arg("password")
        .arg("ssh")
        .arg("admin@localhost")
        .arg("-p")
        .arg("2222")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-v")
        .arg("-T") // Just connect and authenticate, don't allocate a TTY
        .arg("echo 'Client connected successfully!'") // Command to run
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    tokio::select! {
        res = server_handle => println!("[Main] Server task finished with result: {:?}", res),
        status = child.wait() => println!("[Main] SSH client process exited with status: {:?}", status),
    }

    Ok(())
}