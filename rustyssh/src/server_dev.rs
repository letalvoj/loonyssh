use std::convert::TryInto;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

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

struct CryptoState {
    key: Vec<u8>,
    // This simulates the state (keystream position) for a stream cipher.
    bytes_processed: usize,
}

/// A toy stream cipher using a repeating XOR key. This simulates a real stream cipher like AES-CTR.
fn xor_with_keystream(data: &mut [u8], key: &[u8], start_offset: usize) {
    if key.is_empty() {
        return;
    }
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[(start_offset + i) % key.len()];
    }
}

/// Applies the toy XOR cipher and appends a dummy MAC.
fn encrypt_and_mac(
    crypto: &mut CryptoState,
    _sequence_num: u32,
    plaintext_packet: &[u8],
) -> Result<Vec<u8>, std::io::Error> {
    println!("[Server] !! STUB: 'Encrypting' packet with XOR cipher.");
    const MAC_LEN: usize = 32; // for hmac-sha2-256
    let mut encrypted_packet = plaintext_packet.to_vec();
    xor_with_keystream(
        &mut encrypted_packet,
        &crypto.key,
        crypto.bytes_processed,
    );
    crypto.bytes_processed += encrypted_packet.len();
    encrypted_packet.extend_from_slice(&vec![0u8; MAC_LEN]); // Dummy MAC
    Ok(encrypted_packet)
}

/// Reverses the toy XOR cipher and verifies the dummy MAC.
fn decrypt_and_verify(
    crypto: &mut CryptoState,
    _sequence_num: u32,
    packet_with_mac: &[u8],
) -> Result<Vec<u8>, std::io::Error> {
    println!("[Server] !! STUB: 'Decrypting' packet with XOR cipher.");
    const MAC_LEN: usize = 32; // for hmac-sha2-256
    if packet_with_mac.len() < MAC_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Packet too small for MAC",
        ));
    }
    let data_len = packet_with_mac.len() - MAC_LEN;
    let mut encrypted_data = packet_with_mac[..data_len].to_vec();
    xor_with_keystream(&mut encrypted_data, &crypto.key, crypto.bytes_processed);
    crypto.bytes_processed += encrypted_data.len();
    Ok(encrypted_data)
}

fn build_packet(payload: &[u8]) -> Vec<u8> {
    let block_size = 8;

    let unpadded_len = 4 + 1 + payload.len();
    let remainder = unpadded_len % block_size;
    let mut padding_len = if remainder == 0 {
        0
    } else {
        block_size - remainder
    };
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
    server_crypto: &mut Option<CryptoState>,
) -> std::io::Result<()> {
    let mut payload_buf = Vec::new();
    msg.write_ssh(&mut payload_buf)?;

    println!("\n[Server] >> Preparing to send message: {:?}", msg);
    println!(
        "[Server] -> Serialized payload ({} bytes): {}",
        payload_buf.len(),
        format_bytes_as_repr(&payload_buf)
    );

    let framed_packet = build_packet(&payload_buf);

    let packet_to_send = if let Some(ref mut crypto) = server_crypto {
        encrypt_and_mac(crypto, 0, &framed_packet)?
    } else {
        framed_packet
    };

    println!(
        "[Server] -> Full packet to be sent ({} bytes): {}",
        packet_to_send.len(),
        format_bytes_as_repr(&packet_to_send)
    );
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
        let n = socket
            .read(&mut buffer)
            .await
            .expect("Failed to read version");
        buffer.truncate(n);
        let mut len = buffer.len();
        while len > 0 && (buffer[len - 1] == b'\n' || buffer[len - 1] == b'\r') {
            len -= 1;
        }
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
        let mut session_keys: Option<Vec<u8>> = None;
        let mut client_kex_init_payload: Option<Vec<u8>> = None;
        let mut server_kex_init_payload: Option<Vec<u8>> = None;
        let mut authenticated = false;
        let mut session_channel_id: Option<u32> = None;

        // Crypto State
        let mut client_crypto: Option<CryptoState> = None;
        let mut server_crypto: Option<CryptoState> = None;

        loop {
            let mut temp_buf = [0; 1024];
            match timeout(Duration::from_secs(10), rd.read(&mut temp_buf)).await {
                Err(_) => {
                    println!("\n[Server] Timeout.");
                    break;
                }
                Ok(Ok(0)) => {
                    println!("\n[Server] Client disconnected.");
                    break;
                }
                Ok(Ok(n)) => {
                    println!(
                        "\n[Server] << Read {} bytes from socket: {}",
                        n,
                        format_bytes_as_repr(&temp_buf[..n])
                    );
                    read_buffer.extend_from_slice(&temp_buf[..n]);
                    println!(
                        "[Server] -- Read buffer now has {} bytes.",
                        read_buffer.len()
                    );
                }
                Ok(Err(e)) => {
                    eprintln!("\n[Server] Read error: {}", e);
                    break;
                }
            };

            'packet_loop: loop {
                let (packet_body, consumed_size) = if let Some(ref mut crypto) = client_crypto {
                    const BLOCK_SIZE: usize = 16; // AES block size
                    const MAC_LEN: usize = 32;

                    if read_buffer.len() < BLOCK_SIZE {
                        println!("[Server] -- Not enough data for encrypted header (have {}, need {}). Waiting for more.", read_buffer.len(), BLOCK_SIZE);
                        break 'packet_loop;
                    }

                    // Decrypt a *copy* of the header to peek at the length, without modifying the main crypto state
                    let mut header_block_copy = read_buffer[..BLOCK_SIZE].to_vec();
                    xor_with_keystream(&mut header_block_copy, &crypto.key, crypto.bytes_processed);

                    let packet_len =
                        u32::from_be_bytes(header_block_copy[0..4].try_into().unwrap()) as usize;
                    println!("[Server] -- Peeked and found packet length: {}", packet_len);

                    if packet_len > 35000 { // Sanity check from RFC 4253
                        eprintln!("[Server] -- Invalid packet length received: {}. Closing connection.", packet_len);
                        break 'packet_loop;
                    }

                    let packet_body_len = 4 + packet_len;
                    let total_wire_len = packet_body_len + MAC_LEN;

                    if read_buffer.len() < total_wire_len {
                        println!("[Server] -- Incomplete packet on wire (have {}, need {}). Waiting for more.", read_buffer.len(), total_wire_len);
                        break 'packet_loop;
                    }

                    // Now we have the full packet, so we can decrypt it for real and advance the state.
                    let packet_with_mac = &read_buffer[..total_wire_len];
                    let decrypted_packet_body =
                        decrypt_and_verify(crypto, 0, packet_with_mac).unwrap();
                    (decrypted_packet_body, total_wire_len)
                } else {
                    if read_buffer.len() < 4 {
                        break 'packet_loop;
                    }
                    let packet_len =
                        u32::from_be_bytes(read_buffer[0..4].try_into().unwrap()) as usize;
                    let total_len = 4 + packet_len;

                    if read_buffer.len() < total_len {
                        break 'packet_loop;
                    }
                    (read_buffer[..total_len].to_vec(), total_len)
                };

                println!(
                    "[Server] -- Processing packet body ({} bytes total): {}",
                    packet_body.len(),
                    format_bytes_as_repr(&packet_body)
                );
                read_buffer.drain(..consumed_size);

                let padding_length = packet_body[4] as usize;
                let payload_end = packet_body.len() - padding_length;
                if 5 > payload_end || payload_end > packet_body.len() {
                    eprintln!(
                        "[Server] Invalid packet format: padding length {} is invalid for packet size {}",
                        padding_length,
                        packet_body.len()
                    );
                    continue 'packet_loop;
                }

                let raw_packet_payload = &packet_body[5..payload_end];
                println!(
                    "[Server] -- Extracted payload ({} bytes): {}",
                    raw_packet_payload.len(),
                    format_bytes_as_repr(raw_packet_payload)
                );

                let mut cursor = std::io::Cursor::new(raw_packet_payload);
                match read_next_message(&mut cursor) {
                    Ok(msg) => {
                        println!("[Server] -- Parsed message: {:?}", msg);
                        match msg {
                            SSHMsg::KexInit(_) => {
                                client_kex_init_payload = Some(raw_packet_payload.to_vec());
                                let kex_init = MsgKexInit {
                                    cookie: [0; 16],
                                    kex_algorithms: vec!["ecdh-sha2-nistp256".into()],
                                    server_host_key_algorithms: vec!["ssh-ed25519".into()],
                                    encryption_algorithms_client_to_server: vec![
                                        "aes128-ctr".into(),
                                    ],
                                    encryption_algorithms_server_to_client: vec![
                                        "aes128-ctr".into(),
                                    ],
                                    mac_algorithms_client_to_server: vec![
                                        "hmac-sha2-256".into(),
                                    ],
                                    mac_algorithms_server_to_client: vec![
                                        "hmac-sha2-256".into(),
                                    ],
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
                                send_packet(&mut wr, &kex_init, &mut server_crypto)
                                    .await
                                    .unwrap();
                            }
                            SSHMsg::KexECDHInit(req) => {
                                let client_pk =
                                    p256::PublicKey::from_sec1_bytes(&req.q_c).unwrap();
                                let shared = server_ephemeral_secret.diffie_hellman(&client_pk);
                                let mut k = shared.raw_secret_bytes().to_vec();
                                if k.get(0).map_or(false, |&b| b & 0x80 != 0) {
                                    k.insert(0, 0);
                                }

                                let mut k_s = Vec::new();
                                "ssh-ed25519".to_string().write_ssh(&mut k_s).unwrap();
                                host_key
                                    .verifying_key()
                                    .to_bytes()
                                    .to_vec()
                                    .write_ssh(&mut k_s)
                                    .unwrap();

                                let mut h = Sha256::new();
                                client_version_bytes.write_ssh(&mut h).unwrap();
                                server_version
                                    .trim()
                                    .as_bytes()
                                    .to_vec()
                                    .write_ssh(&mut h)
                                    .unwrap();
                                client_kex_init_payload
                                    .as_ref()
                                    .unwrap()
                                    .write_ssh(&mut h)
                                    .unwrap();
                                server_kex_init_payload
                                    .as_ref()
                                    .unwrap()
                                    .write_ssh(&mut h)
                                    .unwrap();
                                k_s.write_ssh(&mut h).unwrap();
                                req.q_c.write_ssh(&mut h).unwrap();
                                server_ephemeral_pk
                                    .to_sec1_bytes()
                                    .to_vec()
                                    .write_ssh(&mut h)
                                    .unwrap();
                                k.write_ssh(&mut h).unwrap();
                                let exchange_hash = h.finalize();
                                session_keys = Some(exchange_hash.to_vec());

                                let signature = host_key.sign(&exchange_hash);
                                let mut sig_blob = Vec::new();
                                "ssh-ed25519".to_string().write_ssh(&mut sig_blob).unwrap();
                                signature
                                    .to_bytes()
                                    .to_vec()
                                    .write_ssh(&mut sig_blob)
                                    .unwrap();

                                let reply = MsgKexECDHReply {
                                    k_s,
                                    q_s: server_ephemeral_pk.to_sec1_bytes().to_vec(),
                                    signature: sig_blob,
                                };
                                send_packet(&mut wr, &reply, &mut server_crypto).await.unwrap();
                            }
                            SSHMsg::NewKeys(_) => {
                                println!("[Server] !! Activating crypto for client->server messages.");
                                client_crypto = Some(CryptoState {
                                    key: session_keys.as_ref().unwrap().clone(),
                                    bytes_processed: 0,
                                });
                                send_packet(&mut wr, &MsgNewKeys {}, &mut server_crypto)
                                    .await
                                    .unwrap();
                                println!("[Server] !! Activating crypto for server->client messages.");
                                server_crypto = Some(CryptoState {
                                    key: session_keys.as_ref().unwrap().clone(),
                                    bytes_processed: 0,
                                });
                            }
                            SSHMsg::ServiceRequest(req) => {
                                if req.service_name == "ssh-userauth" {
                                    let accept =
                                        MsgServiceAccept { service_name: "ssh-userauth".into() };
                                    send_packet(&mut wr, &accept, &mut server_crypto)
                                        .await
                                        .unwrap();
                                } else if req.service_name == "ssh-connection" && authenticated {
                                    let accept = MsgServiceAccept {
                                        service_name: "ssh-connection".into(),
                                    };
                                    send_packet(&mut wr, &accept, &mut server_crypto)
                                        .await
                                        .unwrap();
                                }
                            }
                            SSHMsg::UserauthRequest(req) => match req.method_name.as_str() {
                                "none" => {
                                    let failure = MsgUserauthFailure {
                                        authentications_that_can_continue: vec![
                                            "password".into()
                                        ],
                                        partial_success: false,
                                    };
                                    send_packet(&mut wr, &failure, &mut server_crypto)
                                        .await
                                        .unwrap();
                                }
                                "password" => {
                                    let _has_old_pw: bool =
                                        ReadSSH::read_ssh(&mut cursor).unwrap();
                                    let password_str: String =
                                        ReadSSH::read_ssh(&mut cursor).unwrap();

                                    if req.user_name == "admin" && password_str == "password" {
                                        send_packet(
                                            &mut wr,
                                            &MsgUserauthSuccess {},
                                            &mut server_crypto,
                                        )
                                        .await
                                        .unwrap();
                                        authenticated = true;
                                    } else {
                                        let failure = MsgUserauthFailure {
                                            authentications_that_can_continue: vec![
                                                "password".into(),
                                            ],
                                            partial_success: false,
                                        };
                                        send_packet(&mut wr, &failure, &mut server_crypto)
                                            .await
                                            .unwrap();
                                    }
                                }
                                _ => break 'packet_loop,
                            },
                            SSHMsg::ChannelOpen(req) => {
                                if req.channel_type == "session" {
                                    let server_channel_id = 0; // First channel
                                    session_channel_id = Some(server_channel_id);
                                    let confirmation = MsgChannelOpenConfirmation {
                                        recipient_channel: req.sender_channel,
                                        sender_channel: server_channel_id,
                                        initial_window_size: 2097152,
                                        maximum_packet_size: 32768,
                                    };
                                    send_packet(&mut wr, &confirmation, &mut server_crypto)
                                        .await
                                        .unwrap();
                                }
                            }
                            SSHMsg::ChannelRequest(req) => {
                                if Some(req.recipient_channel) == session_channel_id {
                                    if req.request_type == "exec" {
                                        if req.want_reply {
                                            send_packet(
                                                &mut wr,
                                                &MsgChannelSuccess {
                                                    recipient_channel: req.recipient_channel,
                                                },
                                                &mut server_crypto,
                                            )
                                            .await
                                            .unwrap();
                                        }
                                        let greeting = "Hello from RustySSH server!\n";
                                        let data_msg = MsgChannelData {
                                            recipient_channel: req.recipient_channel,
                                            data: greeting.as_bytes().to_vec(),
                                        };
                                        send_packet(&mut wr, &data_msg, &mut server_crypto)
                                            .await
                                            .unwrap();

                                        let eof_msg = MsgChannelEof {
                                            recipient_channel: req.recipient_channel,
                                        };
                                        send_packet(&mut wr, &eof_msg, &mut server_crypto)
                                            .await
                                            .unwrap();

                                        let close_msg = MsgChannelClose {
                                            recipient_channel: req.recipient_channel,
                                        };
                                        send_packet(&mut wr, &close_msg, &mut server_crypto)
                                            .await
                                            .unwrap();
                                    }
                                }
                            }
                            SSHMsg::ChannelClose(req) => {
                                if Some(req.recipient_channel) == session_channel_id {
                                    println!("[Server] Client closed channel. Closing connection.");
                                    let close_msg = MsgChannelClose {
                                        recipient_channel: req.recipient_channel,
                                    };
                                    send_packet(&mut wr, &close_msg, &mut server_crypto)
                                        .await
                                        .unwrap();
                                    break;
                                }
                            }
                            _ => {
                                println!(
                                    "[Server] Unhandled authenticated message: {:?}. Closing.",
                                    msg
                                );
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Server] Payload parse error: {}. Dropping.", e);
                        continue 'packet_loop;
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