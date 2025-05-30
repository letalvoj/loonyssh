// Allow dead code for now, as tests will be added incrementally
#![allow(dead_code)]

use super::api::*;
use super::msg::*;
use std::io::Cursor;
use pretty_hex::*; // For printing byte arrays during debugging if needed

// Generic helper function for testing message serialization and deserialization
fn test_message_serialization_deserialization<T>(
    msg: T,
) -> Result<SSHMsg, std::io::Error>
where
    T: WriteSSH + ReadSSH + PartialEq + std::fmt::Debug + SSHMagic,
{
    let mut bytes = Vec::new();
    // msg.write_ssh(&mut bytes)?; // This would write the MAGIC byte from T, then fields
                               // However, read_next_message expects only the fields after the initial magic byte.
                               // The write_ssh for message structs (derived via WriteSSH macro) prepends the MAGIC byte.
                               // So, the full output of msg.write_ssh() is what read_next_message should be able to parse
                               // if we strip the first magic byte before giving it to specific MsgType::read_ssh.
                               // BUT read_next_message itself reads the first magic byte. So this is correct.

    msg.write_ssh(&mut bytes)?;

    assert!(!bytes.is_empty(), "Serialized bytes should not be empty");
    assert_eq!(
        bytes[0],
        T::MAGIC,
        "First byte of serialized data should match T::MAGIC"
    );

    let mut cursor = Cursor::new(bytes);
    // read_next_message reads the magic byte from the cursor and then calls the appropriate
    // MsgType::read_ssh for the rest of the data.
    super::msg::read_next_message(&mut cursor)
}

#[test]
fn test_msg_disconnect_serialization_deserialization() {
    // Ensure DisconnectCode derives Clone, or create `original_msg` inside the match for comparison.
    // For now, assuming we'll add Clone to DisconnectCode if needed.
    let original_msg = MsgDisconnect {
        code: DisconnectCode::ProtocolError,
        description: "Test disconnect message".to_string(),
        language: "en-US".to_string(),
    };

    let result = test_message_serialization_deserialization(original_msg.clone());

    match result {
        Ok(SSHMsg::Disconnect(deserialized_msg)) => {
            assert_eq!(original_msg, deserialized_msg);
        }
        Ok(other_msg) => {
            panic!("Expected SSHMsg::Disconnect, but got {:?}", other_msg);
        }
        Err(e) => {
            panic!("Serialization/deserialization failed: {:?}", e);
        }
    }
}

// Helper for testing u32-backed enums
fn test_enum_u32_serialization_deserialization<E>(
    enum_val: E,
    expected_u32: u32,
) where
    E: WriteSSH + ReadSSH + PartialEq + std::fmt::Debug + Copy,
{
    let mut bytes = Vec::new();
    enum_val.write_ssh(&mut bytes).unwrap();
    assert_eq!(bytes, expected_u32.to_be_bytes());

    let mut cursor = Cursor::new(bytes);
    let deserialized_val = E::read_ssh(&mut cursor).unwrap();
    assert_eq!(enum_val, deserialized_val);
}

#[test]
fn test_channel_open_failure_reason_code_serialization() {
    test_enum_u32_serialization_deserialization(
        ChannelOpenFailureReasonCode::AdministrativelyProhibited,
        1u32,
    );
    test_enum_u32_serialization_deserialization(
        ChannelOpenFailureReasonCode::ConnectFailed,
        2u32,
    );
    test_enum_u32_serialization_deserialization(
        ChannelOpenFailureReasonCode::UnknownChannelType,
        3u32,
    );
    test_enum_u32_serialization_deserialization(
        ChannelOpenFailureReasonCode::ResourceShortage,
        4u32,
    );
}

#[test]
fn test_pseudo_terminal_modes_serialization() {
    test_enum_u32_serialization_deserialization(PseudoTerminalModes::TTY_OP_END, 0u32);
    test_enum_u32_serialization_deserialization(PseudoTerminalModes::VINTR, 1u32);
    test_enum_u32_serialization_deserialization(PseudoTerminalModes::VERASE, 3u32);
    // Add a few more representative values
    test_enum_u32_serialization_deserialization(PseudoTerminalModes::ISIG, 50u32);
    test_enum_u32_serialization_deserialization(PseudoTerminalModes::TTY_OP_OSPEED, 129u32);
}

// Helper for testing string-based enums
fn test_string_enum_serialization<E>(
    enum_val: E,
    expected_str: &str,
) where
    E: WriteSSH + ReadSSH + PartialEq + std::fmt::Debug + Clone, // Clone because we might consume enum_val for expected_bytes
{
    // Test serialization
    let mut bytes = Vec::new();
    enum_val.write_ssh(&mut bytes).unwrap();

    let mut expected_bytes = Vec::new();
    (expected_str.len() as u32).write_ssh(&mut expected_bytes).unwrap();
    expected_bytes.extend_from_slice(expected_str.as_bytes());
    assert_eq!(bytes, expected_bytes, "Mismatch for enum variant representing '{}'", expected_str);

    // Test deserialization
    let mut cursor = Cursor::new(bytes);
    let deserialized_val = E::read_ssh(&mut cursor).unwrap();
    assert_eq!(enum_val, deserialized_val, "Mismatch after deserializing for enum variant representing '{}'", expected_str);
}

fn test_string_enum_unknown_variant<E>(
    unknown_string_val: String,
    constructor: fn(String) -> E,
) where
    E: WriteSSH + ReadSSH + PartialEq + std::fmt::Debug + Clone,
{
    let original_enum_unknown = constructor(unknown_string_val.clone());
    
    // Test serialization of Unknown(string)
    let mut bytes_unknown = Vec::new();
    original_enum_unknown.write_ssh(&mut bytes_unknown).unwrap();

    let mut expected_bytes_unknown = Vec::new();
    (unknown_string_val.len() as u32).write_ssh(&mut expected_bytes_unknown).unwrap();
    expected_bytes_unknown.extend_from_slice(unknown_string_val.as_bytes());
    assert_eq!(bytes_unknown, expected_bytes_unknown, "Mismatch for Unknown variant with string '{}'", unknown_string_val);

    // Test deserialization of Unknown(string)
    let mut cursor_unknown = Cursor::new(bytes_unknown);
    let deserialized_unknown = E::read_ssh(&mut cursor_unknown).unwrap();
    assert_eq!(original_enum_unknown, deserialized_unknown, "Mismatch after deserializing Unknown variant with string '{}'", unknown_string_val);
}

#[test]
fn test_key_exchange_method_serialization() {
    test_string_enum_serialization(KeyExchangeMethod::ecdh__sha2__nistp256, "ecdh-sha2-nistp256");
    test_string_enum_unknown_variant("my-kex@example.com".to_string(), KeyExchangeMethod::Unknown);
}

#[test]
fn test_encryption_algorithm_serialization() {
    test_string_enum_serialization(EncryptionAlgorithm::aes128__ctr, "aes128-ctr");
    test_string_enum_serialization(EncryptionAlgorithm::none, "none");
    test_string_enum_unknown_variant("custom-cipher".to_string(), EncryptionAlgorithm::Unknown);
}

#[test]
fn test_mac_algorithm_serialization() {
    test_string_enum_serialization(MACAlgorithm::hmac__sha1, "hmac-sha1");
    test_string_enum_serialization(MACAlgorithm::hmac__sha2__256, "hmac-sha2-256");
    test_string_enum_serialization(MACAlgorithm::none, "none");
    test_string_enum_unknown_variant("custom-mac".to_string(), MACAlgorithm::Unknown);
}

#[test]
fn test_public_key_algorithm_serialization() {
    test_string_enum_serialization(PublicKeyAlgorithm::ssh__rsa, "ssh-rsa");
    test_string_enum_serialization(PublicKeyAlgorithm::ssh__ed25519, "ssh-ed25519");
    test_string_enum_unknown_variant("custom-pubkey".to_string(), PublicKeyAlgorithm::Unknown);
}

#[test]
fn test_compression_algorithm_serialization() {
    test_string_enum_serialization(CompressionAlgorithm::zlib, "zlib");
    test_string_enum_serialization(CompressionAlgorithm::none, "none");
    test_string_enum_unknown_variant("custom-comp".to_string(), CompressionAlgorithm::Unknown);
}

#[test]
fn test_service_serialization() {
    test_string_enum_serialization(Service::ssh__userauth, "ssh-userauth");
    test_string_enum_serialization(Service::ssh__connection, "ssh-connection");
    // Assuming Service does not have an Unknown variant based on its definition
}

#[test]
fn test_authentication_method_serialization() {
    test_string_enum_serialization(AuthenticationMethod::publickey, "publickey");
    test_string_enum_serialization(AuthenticationMethod::password, "password");
    test_string_enum_serialization(AuthenticationMethod::hostBased, "hostBased"); // Note: macro should handle case
    test_string_enum_serialization(AuthenticationMethod::none, "none");
    // Assuming AuthenticationMethod does not have an Unknown variant
}

#[test]
fn test_connection_protocol_channel_type_serialization() {
    test_string_enum_serialization(ConnectionProtocolChannelType::session, "session");
    test_string_enum_serialization(ConnectionProtocolChannelType::x11, "x11");
    test_string_enum_serialization(ConnectionProtocolChannelType::forwarded__tcpip, "forwarded-tcpip");
    test_string_enum_serialization(ConnectionProtocolChannelType::direct__tcpip, "direct-tcpip");
    // Assuming ConnectionProtocolChannelType does not have an Unknown variant
}

#[test]
fn test_connection_protocol_request_type_serialization() {
    test_string_enum_serialization(ConnectionProtocolRequestType::tcpip__forward, "tcpip-forward");
    test_string_enum_serialization(ConnectionProtocolRequestType::cancel__tcpip__forward, "cancel-tcpip-forward");
    // Assuming ConnectionProtocolRequestType does not have an Unknown variant
}

#[test]
fn test_connection_protocol_channel_request_name_serialization() {
    test_string_enum_serialization(ConnectionProtocolChannelRequestName::pty__req, "pty-req");
    test_string_enum_serialization(ConnectionProtocolChannelRequestName::shell, "shell");
    test_string_enum_serialization(ConnectionProtocolChannelRequestName::exit__signal, "exit-signal");
    // Assuming ConnectionProtocolChannelRequestName does not have an Unknown variant
}

#[test]
fn test_signal_name_serialization() {
    // The erroneous call to test_enum_u32_serialization_deserialization has been removed.
    // Reframing SignalName test as string based.
    // The derive macro for Read/WriteSSH for string enums expects string-based values.
    // SignalName is currently derived as simple names, not u32.
    // The previous change to add Copy to SignalName was an error, it should be Clone only if it's string based
    // Let's assume it's meant to be string based like others without explicit repr(u32)
    test_string_enum_serialization(SignalName::ABRT, "ABRT");
    test_string_enum_serialization(SignalName::KILL, "KILL");
    // Assuming SignalName does not have an Unknown variant
}

// --- Edge Case and Error Handling Tests ---

#[test]
fn test_read_next_message_invalid_magic() {
    let invalid_magic_bytes = [255u8, 0, 0, 0]; // 255 is not a valid SSH message type
    let mut cursor = Cursor::new(&invalid_magic_bytes[..]);
    let result = super::msg::read_next_message(&mut cursor);
    assert!(result.is_err(), "Expected an error for invalid magic number");
    if let Err(e) = result {
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "Error kind should be InvalidData for unknown magic number");
    }
}

#[test]
fn test_read_next_message_insufficient_data() {
    // MsgUnimplemented requires a u32, so 4 bytes after magic. We provide only 2.
    let insufficient_data_bytes = [MsgUnimplemented::MAGIC, 1, 2]; 
    let mut cursor = Cursor::new(&insufficient_data_bytes[..]);
    let result = super::msg::read_next_message(&mut cursor);
    assert!(result.is_err(), "Expected an error for insufficient data after magic number");
    if let Err(e) = result {
        // This will likely be UnexpectedEof because read_u32 will try to read 4 bytes.
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "Error kind should be UnexpectedEof for insufficient data for MsgUnimplemented payload");
    }
}

#[test]
fn test_string_read_ssh_malformed_data() {
    // Scenario 1: Length declares more bytes than available
    let bytes_len_too_long = [0u8, 0, 0, 10, b'h', b'e', b'l', b'l', b'o']; // Length 10, actual "hello" (5 bytes)
    let mut cursor1 = Cursor::new(&bytes_len_too_long[..]);
    let result1 = String::read_ssh(&mut cursor1);
    assert!(result1.is_err(), "Expected error for string length > available bytes");
    if let Err(e) = result1 {
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "Error kind should be UnexpectedEof for string length > available");
    }

    // Scenario 2: Invalid UTF-8 sequence
    let bytes_invalid_utf8 = [0u8, 0, 0, 4, 0xC3, 0x28, 0xA0, 0xA1]; // Invalid UTF-8 sequence \xC3\x28
    let mut cursor2 = Cursor::new(&bytes_invalid_utf8[..]);
    let result2 = String::read_ssh(&mut cursor2);
    assert!(result2.is_err(), "Expected error for invalid UTF-8 sequence");
    if let Err(e) = result2 {
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "Error kind should be InvalidData for invalid UTF-8");
    }
}

#[test]
fn test_name_list_read_ssh_malformed_data() {
    // Scenario 1: Name-list length declares more bytes than available
    let bytes_len_too_long = [0u8, 0, 0, 20, b'a', b',', b'b']; // Length 20, actual "a,b" (3 bytes)
    let mut cursor1 = Cursor::new(&bytes_len_too_long[..]);
    let result1 = Vec::<String>::read_ssh(&mut cursor1);
    assert!(result1.is_err(), "Expected error for name-list length > available bytes");
    if let Err(e) = result1 {
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "Error kind should be UnexpectedEof for name-list length > available");
    }

    // Scenario 2: Invalid UTF-8 sequence in name-list
    let bytes_invalid_utf8 = [0u8, 0, 0, 4, 0xC3, 0x28, 0xA0, 0xA1]; // Invalid UTF-8 sequence \xC3\x28
    let mut cursor2 = Cursor::new(&bytes_invalid_utf8[..]);
    let result2 = Vec::<String>::read_ssh(&mut cursor2);
    assert!(result2.is_err(), "Expected error for invalid UTF-8 sequence in name-list");
    if let Err(e) = result2 {
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "Error kind should be InvalidData for invalid UTF-8 in name-list");
    }
}

#[test]
fn test_u32_enum_invalid_discriminant() {
    // ChannelOpenFailureReasonCode max valid discriminant is 4. Use 5.
    let invalid_discriminant_bytes = 5u32.to_be_bytes();
    let mut cursor = Cursor::new(&invalid_discriminant_bytes[..]);
    let result = ChannelOpenFailureReasonCode::read_ssh(&mut cursor);
    assert!(result.is_err(), "Expected error for invalid u32 enum discriminant");
    if let Err(e) = result {
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "Error kind should be InvalidData for invalid u32 enum discriminant");
    }
}

#[test]
fn test_string_enum_invalid_variant() {
    // Service enum does not have an "Unknown" variant.
    let invalid_variant_str = "this-is-not-a-valid-service-name";
    let mut bytes = Vec::new();
    // Manually serialize this string as if it were a name-list/string payload
    (invalid_variant_str.len() as u32).write_ssh(&mut bytes).unwrap();
    bytes.extend_from_slice(invalid_variant_str.as_bytes());
    
    let mut cursor = Cursor::new(&bytes[..]);
    let result = Service::read_ssh(&mut cursor);
    assert!(result.is_err(), "Expected error for invalid string enum variant");
    if let Err(e) = result {
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "Error kind should be InvalidData for invalid string enum variant");
    }
}

#[test]
fn test_msg_kex_init_serialization_deserialization() {
    // Scenario 1: Empty Name-Lists
    let original_msg_empty = MsgKexInit {
        cookie: [1u8; 16],
        kex_algorithms: Vec::new(),
        server_host_key_algorithms: Vec::new(),
        encryption_algorithms_client_to_server: Vec::new(),
        encryption_algorithms_server_to_client: Vec::new(),
        mac_algorithms_client_to_server: Vec::new(),
        mac_algorithms_server_to_client: Vec::new(),
        compression_algorithms_client_to_server: Vec::new(),
        compression_algorithms_server_to_client: Vec::new(),
        languages_client_to_server: Vec::new(),
        languages_server_to_client: Vec::new(),
        kex_first_packet_follows: false,
        reserved: 0,
    };

    let result_empty = test_message_serialization_deserialization(original_msg_empty.clone());
    match result_empty {
        Ok(SSHMsg::KexInit(deserialized_msg)) => {
            assert_eq!(original_msg_empty, deserialized_msg);
        }
        Ok(other_msg) => panic!("Scenario 1 (empty lists): Expected SSHMsg::KexInit, but got {:?}", other_msg),
        Err(e) => panic!("Scenario 1 (empty lists) failed: {:?}", e),
    }

    // Scenario 2: Single Item Name-Lists
    let original_msg_single = MsgKexInit {
        cookie: [2u8; 16],
        kex_algorithms: vec!["curve25519-sha256".to_string()],
        server_host_key_algorithms: vec!["ssh-ed25519".to_string()],
        encryption_algorithms_client_to_server: vec!["aes128-ctr".to_string()],
        encryption_algorithms_server_to_client: vec!["aes128-ctr".to_string()],
        mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_string()],
        mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_string()],
        compression_algorithms_client_to_server: vec!["none".to_string()],
        compression_algorithms_server_to_client: vec!["none".to_string()],
        languages_client_to_server: vec!["en-US".to_string()],
        languages_server_to_client: vec!["en-US".to_string()],
        kex_first_packet_follows: true,
        reserved: 0,
    };

    let result_single = test_message_serialization_deserialization(original_msg_single.clone());
    match result_single {
        Ok(SSHMsg::KexInit(deserialized_msg)) => {
            assert_eq!(original_msg_single, deserialized_msg);
        }
        Ok(other_msg) => panic!("Scenario 2 (single item): Expected SSHMsg::KexInit, but got {:?}", other_msg),
        Err(e) => panic!("Scenario 2 (single item) failed: {:?}", e),
    }

    // Scenario 3: Multiple Item Name-Lists
    let original_msg_multiple = MsgKexInit {
        cookie: [3u8; 16],
        kex_algorithms: vec!["curve25519-sha256".to_string(), "diffie-hellman-group-exchange-sha256".to_string()],
        server_host_key_algorithms: vec!["ssh-ed25519".to_string(), "rsa-sha2-512".to_string()],
        encryption_algorithms_client_to_server: vec!["aes128-ctr".to_string(), "aes256-ctr".to_string()],
        encryption_algorithms_server_to_client: vec!["aes128-ctr".to_string(), "aes256-ctr".to_string()],
        mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_string(), "hmac-sha1".to_string()],
        mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_string(), "hmac-sha1".to_string()],
        compression_algorithms_client_to_server: vec!["none".to_string(), "zlib@openssh.com".to_string()],
        compression_algorithms_server_to_client: vec!["none".to_string(), "zlib@openssh.com".to_string()],
        languages_client_to_server: vec!["en-US".to_string(), "en-GB".to_string()],
        languages_server_to_client: vec!["en-US".to_string(), "en-GB".to_string()],
        kex_first_packet_follows: false,
        reserved: 0,
    };

    let result_multiple = test_message_serialization_deserialization(original_msg_multiple.clone());
    match result_multiple {
        Ok(SSHMsg::KexInit(deserialized_msg)) => {
            assert_eq!(original_msg_multiple, deserialized_msg);
        }
        Ok(other_msg) => panic!("Scenario 3 (multiple items): Expected SSHMsg::KexInit, but got {:?}", other_msg),
        Err(e) => panic!("Scenario 3 (multiple items) failed: {:?}", e),
    }

    // Scenario 4: Mixed Empty and Non-Empty Name-Lists
    let original_msg_mixed = MsgKexInit {
        cookie: [4u8; 16],
        kex_algorithms: vec!["curve25519-sha256".to_string()],
        server_host_key_algorithms: Vec::new(), // Empty
        encryption_algorithms_client_to_server: vec!["aes128-ctr".to_string(), "aes256-ctr".to_string()],
        encryption_algorithms_server_to_client: Vec::new(), // Empty
        mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_string()],
        mac_algorithms_server_to_client: Vec::new(), // Empty
        compression_algorithms_client_to_server: vec!["none".to_string(), "zlib@openssh.com".to_string()],
        compression_algorithms_server_to_client: Vec::new(), // Empty
        languages_client_to_server: vec!["en-US".to_string()],
        languages_server_to_client: Vec::new(), // Empty
        kex_first_packet_follows: true,
        reserved: 0,
    };

    let result_mixed = test_message_serialization_deserialization(original_msg_mixed.clone());
    match result_mixed {
        Ok(SSHMsg::KexInit(deserialized_msg)) => {
            assert_eq!(original_msg_mixed, deserialized_msg);
        }
        Ok(other_msg) => panic!("Scenario 4 (mixed): Expected SSHMsg::KexInit, but got {:?}", other_msg),
        Err(e) => panic!("Scenario 4 (mixed) failed: {:?}", e),
    }
}

#[test]
fn test_msg_ignore_serialization_deserialization() {
    let original_msg = MsgIgnore {
        data: "Test ignore message".to_string(),
    };

    let result = test_message_serialization_deserialization(original_msg.clone());

    match result {
        Ok(SSHMsg::Ignore(deserialized_msg)) => {
            assert_eq!(original_msg, deserialized_msg);
        }
        Ok(other_msg) => {
            panic!("Expected SSHMsg::Ignore, but got {:?}", other_msg);
        }
        Err(e) => {
            panic!("Serialization/deserialization failed: {:?}", e);
        }
    }
}

#[test]
fn test_msg_unimplemented_serialization_deserialization() {
    let original_msg = MsgUnimplemented {
        packet_sequence_number: 12345,
    };

    let result = test_message_serialization_deserialization(original_msg.clone());

    match result {
        Ok(SSHMsg::Unimplemented(deserialized_msg)) => {
            assert_eq!(original_msg, deserialized_msg);
        }
        Ok(other_msg) => {
            panic!("Expected SSHMsg::Unimplemented, but got {:?}", other_msg);
        }
        Err(e) => {
            panic!("Serialization/deserialization failed: {:?}", e);
        }
    }
}

#[test]
fn test_msg_debug_serialization_deserialization() {
    let original_msg = MsgDebug {
        always_display: true,
        message: "Test debug message".to_string(),
        language: "en-GB".to_string(),
    };

    let result = test_message_serialization_deserialization(original_msg.clone());

    match result {
        Ok(SSHMsg::Debug(deserialized_msg)) => {
            assert_eq!(original_msg, deserialized_msg);
        }
        Ok(other_msg) => {
            panic!("Expected SSHMsg::Debug, but got {:?}", other_msg);
        }
        Err(e) => {
            panic!("Serialization/deserialization failed: {:?}", e);
        }
    }
}

#[test]
fn test_msg_newkeys_serialization_deserialization() {
    let original_msg = MsgNewKeys {}; // Unit struct

    // Explicitly clone, even for Copy types, for consistency and to satisfy the borrow checker after move.
    let result = test_message_serialization_deserialization(original_msg.clone()); 

    match result {
        Ok(SSHMsg::NewKeys(deserialized_msg)) => {
            assert_eq!(original_msg, deserialized_msg);
        }
        Ok(other_msg) => {
            panic!("Expected SSHMsg::NewKeys, but got {:?}", other_msg);
        }
        Err(e) => {
            panic!("Serialization/deserialization failed: {:?}", e);
        }
    }
}
