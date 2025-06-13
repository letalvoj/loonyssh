use std::io::{Cursor, Read, Write}; // Cursor re-added
use std::net::TcpStream;
use std::process;
use std::time::Duration;

use rand::RngCore; // Added for random cookie

mod api;
mod msg;

use pretty_hex::*;

use crate::api::WriteSSH;
use crate::msg::*;

fn main() -> std::io::Result<()> {
    // Attempt to establish a TCP connection
    match TcpStream::connect("localhost:22") {
        Ok(mut stream) => {
            println!("Successfully connected to localhost:22");

            let protocol_version = "SSH-2.0-rustyssh_0.1.0\r\n";
            println!("Sending protocol version: {}", protocol_version.trim_end()); // Log without CRLF for cleaner output
            if let Err(e) = stream.write_all(protocol_version.as_bytes()) {
                eprintln!("Failed to send protocol version: {}", e);
                process::exit(1);
            }

            // Set a read timeout
            if let Err(e) = stream.set_read_timeout(Some(Duration::new(5, 0))) {
                eprintln!("Failed to set read timeout: {}", e);
                process::exit(1);
            }

            // Read the server's protocol version string
            let mut buffer = [0u8; 256];
            match stream.read(&mut buffer) {
                Ok(n) => {
                    if n == 0 {
                        eprintln!("Server closed connection prematurely while reading protocol string.");
                        process::exit(1);
                    }
                    let server_response = String::from_utf8_lossy(&buffer[..n]);
                    println!("Received from server: {}", server_response.trim());

                    // Parse the server's protocol string
                    // It should be something like "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
                    // We need to extract "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
                    let mut parts = server_response.trim_end().splitn(2, "\r\n");
                    let server_protocol_string = parts.next().unwrap_or("").trim();


                    if server_protocol_string.starts_with("SSH-2.0-") {
                        println!("Parsed server protocol version: {}", server_protocol_string);
                    } else {
                        eprintln!(
                            "Invalid server protocol string format. Expected 'SSH-2.0-...', got: {}",
                            server_response.trim()
                        );
                        process::exit(1);
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
                        eprintln!("Timeout waiting for server protocol string.");
                    } else {
                        eprintln!("Failed to read server protocol string: {}", e);
                    }
                    process::exit(1);
                }
            }

            // Construct MsgKexInit
            let mut cookie = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut cookie);

            let kex_init_payload = MsgKexInit {
                cookie,
                kex_algorithms: vec![
                    "ecdh-sha2-nistp256".to_string(),
                    "diffie-hellman-group-exchange-sha256".to_string(),
                    "diffie-hellman-group14-sha256".to_string(),
                ],
                server_host_key_algorithms: vec![
                    "ssh-ed25519".to_string(),
                    "rsa-sha2-512".to_string(),
                    "rsa-sha2-256".to_string(),
                    "ssh-rsa".to_string(),
                ],
                encryption_algorithms_client_to_server: vec![
                    "aes128-ctr".to_string(),
                    "aes192-ctr".to_string(),
                    "aes256-ctr".to_string(),
                ],
                encryption_algorithms_server_to_client: vec![
                    "aes128-ctr".to_string(),
                    "aes192-ctr".to_string(),
                    "aes256-ctr".to_string(),
                ],
                mac_algorithms_client_to_server: vec![
                    "hmac-sha2-256".to_string(),
                    "hmac-sha1".to_string(),
                ],
                mac_algorithms_server_to_client: vec![
                    "hmac-sha2-256".to_string(),
                    "hmac-sha1".to_string(),
                ],
                compression_algorithms_client_to_server: vec!["none".to_string()],
                compression_algorithms_server_to_client: vec!["none".to_string()],
                languages_client_to_server: Vec::new(),
                languages_server_to_client: Vec::new(),
                kex_first_packet_follows: false,
                reserved: 0, // As per RFC 4253, this should be 0
            };

            // Serialize into a byte array
            let mut kex_init_bytes = Vec::new();
            kex_init_payload.write_ssh(&mut kex_init_bytes)?;

            println!("Sending KEXINIT: {:?}", kex_init_payload);
            println!("KEXINIT Bytes: {:?}", kex_init_bytes.hex_dump());

            // Send KEXINIT message
            if let Err(e) = stream.write_all(&kex_init_bytes) {
                eprintln!("Failed to send KEXINIT message: {}", e);
                process::exit(1);
            }

            // For now, we are not processing the server's KEXINIT response
            // The old deserialization test code is removed.

            // Set read timeout again for server's KEXINIT
            if let Err(e) = stream.set_read_timeout(Some(Duration::new(5, 0))) {
                eprintln!("Failed to set read timeout for server KEXINIT: {}", e);
                process::exit(1);
            }

            // Read the server's KEXINIT response
            let mut kex_buffer = [0u8; 4096]; // Buffer for KEXINIT
            match stream.read(&mut kex_buffer) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        eprintln!("Server closed connection while waiting for KEXINIT.");
                        process::exit(1);
                    }
                    println!(
                        "Received KEXINIT raw bytes ({} bytes): {:?}",
                        bytes_read,
                        (&kex_buffer[..bytes_read]).hex_dump()
                    );

                    if bytes_read < 5 {
                        eprintln!("Error: Received KEXINIT packet too short to contain length and padding info ({} bytes).", bytes_read);
                        process::exit(1);
                    }

                    let packet_length = u32::from_be_bytes(kex_buffer[0..4].try_into().expect("Slice for packet_length is wrong size"));
                    let padding_length = kex_buffer[4];

                    // payload_in_packet_offset is the offset of the SSH message type code from the start of kex_buffer
                    let payload_in_packet_offset = 5;

                    // msg_payload_length is the length of the SSH message itself (e.g. KEXINIT data)
                    // It does not include the packet_length field, padding_length field, or the random padding itself.
                    if packet_length < (padding_length as u32 + 1) {
                        eprintln!("Error: Invalid packet structure. packet_length ({}) is too small to accommodate padding_length ({}) + 1 byte for msg type.", packet_length, padding_length);
                        process::exit(1);
                    }
                    let msg_payload_length = packet_length as usize - padding_length as usize - 1;

                    // total_expected_bytes_for_this_packet is 4 (packet_length field) + its value (packet_length)
                    let total_expected_bytes_for_this_packet = 4 + packet_length as usize;

                    if bytes_read < total_expected_bytes_for_this_packet {
                        eprintln!(
                            "Error: Incomplete packet. Expected {} bytes for the full SSH packet based on its length field, but only received {} bytes.",
                            total_expected_bytes_for_this_packet, bytes_read
                        );
                        // This could be a legitimate partial read, but for now, we'll treat it as an error.
                        // A more robust client might buffer and retry reading.
                        process::exit(1);
                    }

                    // The cursor should operate on the SSH message payload part of the buffer
                    let ssh_message_payload_slice = &kex_buffer[payload_in_packet_offset .. payload_in_packet_offset + msg_payload_length];

                    let mut cursor = Cursor::new(ssh_message_payload_slice);
                    match read_next_message(&mut cursor) {
                        Ok(SSHMsg::KexInit(server_kex_init)) => {
                            println!("Successfully parsed server KEXINIT: {:?}", server_kex_init);

                            // Check if read_next_message consumed the entire payload it was given
                            if cursor.position() < msg_payload_length as u64 {
                                eprintln!(
                                    "Error: Did not consume entire KEXINIT message payload. Payload length: {}, Parsed: {}. Unparsed part: {:?}",
                                    msg_payload_length,
                                    cursor.position(),
                                    (&ssh_message_payload_slice[cursor.position() as usize..]).hex_dump()
                                );
                                process::exit(1);
                            }

                            // Check if there are any extra unparsed bytes beyond the current SSH packet in the buffer
                            if bytes_read > total_expected_bytes_for_this_packet {
                                eprintln!(
                                    "Error: Trailing bytes ({}) received after the current SSH packet. Total read: {}, Expected for packet: {}. Trailing data: {:?}",
                                    bytes_read - total_expected_bytes_for_this_packet,
                                    bytes_read,
                                    total_expected_bytes_for_this_packet,
                                    (&kex_buffer[total_expected_bytes_for_this_packet..bytes_read]).hex_dump()
                                );
                                process::exit(1);
                            }

                            // Algorithm Negotiation
                            println!("\n--- Algorithm Negotiation ---");

                            fn find_first_common(client_list: &[String], server_list: &[String]) -> Option<String> {
                                client_list.iter().find(|algo| server_list.contains(algo)).cloned()
                            }

                            let chosen_kex_algo = find_first_common(
                                &kex_init_payload.kex_algorithms,
                                &server_kex_init.kex_algorithms,
                            );
                            match chosen_kex_algo {
                                Some(algo) if algo == "ecdh-sha2-nistp256" => {
                                    println!("Chosen KEX algorithm: {}", algo);
                                    // Store for later: let chosen_kex_algo = algo;
                                }
                                Some(algo) => {
                                    eprintln!("Unsupported KEX algorithm chosen: {}. We only support 'ecdh-sha2-nistp256'.", algo);
                                    process::exit(1);
                                }
                                None => {
                                    eprintln!("No common KEX algorithm found.");
                                    eprintln!("Client offered: {:?}", kex_init_payload.kex_algorithms);
                                    eprintln!("Server offered: {:?}", server_kex_init.kex_algorithms);
                                    process::exit(1);
                                }
                            }

                            let chosen_host_key_algo = find_first_common(
                                &kex_init_payload.server_host_key_algorithms,
                                &server_kex_init.server_host_key_algorithms,
                            );
                            match chosen_host_key_algo {
                                Some(algo) => println!("Chosen server host key algorithm: {}", algo),
                                None => {
                                    eprintln!("No common server host key algorithm found.");
                                    process::exit(1);
                                }
                            }

                            let chosen_enc_c2s = find_first_common(
                                &kex_init_payload.encryption_algorithms_client_to_server,
                                &server_kex_init.encryption_algorithms_client_to_server,
                            );
                            match chosen_enc_c2s {
                                Some(algo) if algo == "aes128-ctr" => {
                                     println!("Chosen client-to-server encryption algorithm: {}", algo);
                                }
                                Some(algo) => {
                                    eprintln!("Unsupported C2S encryption algorithm chosen: {}. We only support 'aes128-ctr'.", algo);
                                    process::exit(1);
                                }
                                None => {
                                    eprintln!("No common client-to-server encryption algorithm found.");
                                    process::exit(1);
                                }
                            }

                            let chosen_enc_s2c = find_first_common(
                                &kex_init_payload.encryption_algorithms_server_to_client,
                                &server_kex_init.encryption_algorithms_server_to_client,
                            );
                             match chosen_enc_s2c {
                                Some(algo) if algo == "aes128-ctr" => {
                                     println!("Chosen server-to-client encryption algorithm: {}", algo);
                                }
                                Some(algo) => {
                                    eprintln!("Unsupported S2C encryption algorithm chosen: {}. We only support 'aes128-ctr'.", algo);
                                    process::exit(1);
                                }
                                None => {
                                    eprintln!("No common server-to-client encryption algorithm found.");
                                    process::exit(1);
                                }
                            }

                            let chosen_mac_c2s = find_first_common(
                                &kex_init_payload.mac_algorithms_client_to_server,
                                &server_kex_init.mac_algorithms_client_to_server,
                            );
                            match chosen_mac_c2s {
                                Some(algo) if algo == "hmac-sha2-256" => {
                                     println!("Chosen client-to-server MAC algorithm: {}", algo);
                                }
                                Some(algo) => {
                                    eprintln!("Unsupported C2S MAC algorithm chosen: {}. We only support 'hmac-sha2-256'.", algo);
                                    process::exit(1);
                                }
                                None => {
                                    eprintln!("No common client-to-server MAC algorithm found.");
                                    process::exit(1);
                                }
                            }

                            let chosen_mac_s2c = find_first_common(
                                &kex_init_payload.mac_algorithms_server_to_client,
                                &server_kex_init.mac_algorithms_server_to_client,
                            );
                            match chosen_mac_s2c {
                                Some(algo) if algo == "hmac-sha2-256" => {
                                     println!("Chosen server-to-client MAC algorithm: {}", algo);
                                }
                                 Some(algo) => {
                                    eprintln!("Unsupported S2C MAC algorithm chosen: {}. We only support 'hmac-sha2-256'.", algo);
                                    process::exit(1);
                                }
                                None => {
                                    eprintln!("No common server-to-client MAC algorithm found.");
                                    process::exit(1);
                                }
                            }

                            // Compression (assuming "none" is the only one we offer/accept for now)
                            if kex_init_payload.compression_algorithms_client_to_server.get(0).map(String::as_str) == Some("none") &&
                               server_kex_init.compression_algorithms_client_to_server.get(0).map(String::as_str) == Some("none") {
                                println!("Chosen client-to-server compression: none");
                            } else {
                                eprintln!("Failed to agree on 'none' for C2S compression.");
                                process::exit(1);
                            }
                             if kex_init_payload.compression_algorithms_server_to_client.get(0).map(String::as_str) == Some("none") &&
                               server_kex_init.compression_algorithms_server_to_client.get(0).map(String::as_str) == Some("none") {
                                println!("Chosen server-to-client compression: none");
                            } else {
                                eprintln!("Failed to agree on 'none' for S2C compression.");
                                process::exit(1);
                            }
                            println!("--- Algorithm Negotiation Complete ---");

                            // Part 2: ECDH Key Generation (if ecdh-sha2-nistp256 is chosen)
                            // We've already confirmed chosen_kex_algo is Some("ecdh-sha2-nistp256")
                            // so we can proceed.

                            use openssl::bn::BigNumContext;
                            use openssl::ec::{EcGroup, EcKey, PointConversionForm};
                            use openssl::nid::Nid;
                            use rand::Rng; // For random padding

                            println!("\n--- ECDH Key Exchange (ecdh-sha2-nistp256) ---");

                            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to create EC group: {}", e)))?;
                            let ec_key = EcKey::generate(&group)
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to generate EC key: {}", e)))?;

                            let mut bn_ctx = BigNumContext::new()
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to create BigNumContext: {}", e)))?;

                            let q_c_bytes = ec_key.public_key().to_bytes(
                                &group,
                                PointConversionForm::UNCOMPRESSED,
                                &mut bn_ctx,
                            ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to get public key bytes: {}", e)))?;

                            println!("Client ephemeral public key (Q_C) generated ({} bytes): {:?}", q_c_bytes.len(), q_c_bytes.hex_dump());

                            // Part 3: Construct and Send MsgKexEcdhInit
                            let kex_ecdh_init_msg = MsgKexECDHInit { q_c: q_c_bytes };

                            let mut kex_ecdh_init_payload_bytes = Vec::new();
                            // Manually write MAGIC first, then the struct for KexEcdhInit
                            // because write_ssh on the struct itself doesn't add the MAGIC.
                            // Correction: The derive ReadSSH/WriteSSH for enums like SSHMsg handles the magic.
                            // When calling write_ssh on a specific message struct, we are writing the payload *after* magic.
                            // The `read_next_message` reads magic then calls specific `Msg::read_ssh`.
                            // So, for sending, we serialize the struct, then prepend magic for the payload.
                            // No, this is also not quite right. write_ssh for the struct is for its fields.
                            // The actual message construction should be:
                            // 1. Create struct (e.g. kex_ecdh_init_msg)
                            // 2. Create a Vec, write MAGIC to it.
                            // 3. Call kex_ecdh_init_msg.write_ssh(&mut Vec) to append fields.
                            // This Vec is then the "SSH Message Payload" for packetization.

                            // kex_ecdh_init_payload_bytes.push(MsgKexECDHInit::MAGIC); // Removed: derived write_ssh should handle MAGIC
                            kex_ecdh_init_msg.write_ssh(&mut kex_ecdh_init_payload_bytes)?;

                            println!("Serialized MsgKexEcdhInit SSH message (incl. MAGIC, {} bytes): {:?}", kex_ecdh_init_payload_bytes.len(), kex_ecdh_init_payload_bytes.hex_dump());

                            // Packet construction
                            let block_size = 8; // Cipher block size (or 8 if no cipher yet)
                            let payload_len = kex_ecdh_init_payload_bytes.len();

                            // Calculate padding length: must be at least 4 bytes
                            // total length of (padding_length_byte + payload + padding) must be multiple of block_size
                            let mut padding_length = block_size - (1 + payload_len) % block_size;
                            if padding_length < 4 {
                                padding_length += block_size;
                            }
                            if padding_length >= 256 { // Should not happen with typical payloads and block_size
                                eprintln!("Calculated excessive padding: {}", padding_length);
                                process::exit(1);
                            }


                            let packet_len_field = (1 + payload_len + padding_length) as u32; // padding_length_byte + payload + random_padding

                            let mut final_packet_bytes = Vec::new();
                            final_packet_bytes.extend_from_slice(&packet_len_field.to_be_bytes());
                            final_packet_bytes.push(padding_length as u8);
                            final_packet_bytes.extend_from_slice(&kex_ecdh_init_payload_bytes);

                            let mut padding_bytes = vec![0u8; padding_length];
                            rand::thread_rng().fill(&mut padding_bytes[..]); // Removed ?
                            final_packet_bytes.extend_from_slice(&padding_bytes);

                            println!("Sending SSH_MSG_KEX_ECDH_INIT ({} bytes packet): {:?}", final_packet_bytes.len(), final_packet_bytes.hex_dump());
                            println!("  Packet Length Field: {}", packet_len_field);
                            println!("  Padding Length Field: {}", padding_length);
                            println!("  Payload (MsgKexEcdhInit with MAGIC): {} bytes", payload_len);
                            println!("  Padding: {} bytes", padding_length);


                            if let Err(e) = stream.write_all(&final_packet_bytes) {
                                eprintln!("Failed to send SSH_MSG_KEX_ECDH_INIT: {}", e);
                                process::exit(1);
                            }
                            println!("SSH_MSG_KEX_ECDH_INIT sent.");

                            // Next step would be to read MsgKexEcdhReply...
                        }
                        Ok(other_msg) => {
                            eprintln!("Unexpected SSH message received instead of KEXINIT (parsed from payload): {:?}", other_msg);
                            process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("Failed to parse server KEXINIT message: {}", e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
                        eprintln!("Timeout waiting for server KEXINIT message.");
                    } else {
                        eprintln!("Failed to read server KEXINIT message: {}", e);
                    }
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to localhost:22: {}", e);
            process::exit(1);
        }
    }
    Ok(())
}
