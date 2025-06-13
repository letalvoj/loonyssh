use crate::api::{ReadSSH, WriteSSH};
pub use ::rustyssh_derive::{ReadSSH, WriteSSH};

pub trait SSHMagic {
    const MAGIC: u8;
}

#[allow(dead_code)]
pub fn read_next_message<R: std::io::Read>(mut reader: R) -> Result<SSHMsg, std::io::Error> {
    let magic: u8 = u8::read_ssh(&mut reader)?;

    match magic {
        MsgDisconnect::MAGIC => MsgDisconnect::read_ssh(reader).map(SSHMsg::Disconnect),
        MsgIgnore::MAGIC => MsgIgnore::read_ssh(reader).map(SSHMsg::Ignore),
        MsgUnimplemented::MAGIC => MsgUnimplemented::read_ssh(reader).map(SSHMsg::Unimplemented),
        MsgDebug::MAGIC => MsgDebug::read_ssh(reader).map(SSHMsg::Debug),
        MsgServiceRequest::MAGIC => MsgServiceRequest::read_ssh(reader).map(SSHMsg::ServiceRequest),
        MsgServiceAccept::MAGIC => MsgServiceAccept::read_ssh(reader).map(SSHMsg::ServiceAccept),
        MsgKexInit::MAGIC => MsgKexInit::read_ssh(reader).map(SSHMsg::KexInit),
        MsgNewKeys::MAGIC => MsgNewKeys::read_ssh(reader).map(SSHMsg::NewKeys),
        MsgKexECDHInit::MAGIC => MsgKexECDHInit::read_ssh(reader).map(SSHMsg::KexECDHInit),
        MsgKexECDHReply::MAGIC => MsgKexECDHReply::read_ssh(reader).map(SSHMsg::KexECDHReply),
        MsgUserauthRequest::MAGIC => MsgUserauthRequest::read_ssh(reader).map(SSHMsg::UserauthRequest),
        MsgUserauthFailure::MAGIC => MsgUserauthFailure::read_ssh(reader).map(SSHMsg::UserauthFailure),
        MsgUserauthSuccess::MAGIC => MsgUserauthSuccess::read_ssh(reader).map(SSHMsg::UserauthSuccess),
        MsgUserauthBanner::MAGIC => MsgUserauthBanner::read_ssh(reader).map(SSHMsg::UserauthBanner),
        MsgGlobalRequest::MAGIC => MsgGlobalRequest::read_ssh(reader).map(SSHMsg::GlobalRequest),
        MsgRequestSuccess::MAGIC => MsgRequestSuccess::read_ssh(reader).map(SSHMsg::RequestSuccess),
        MsgRequestFailure::MAGIC => MsgRequestFailure::read_ssh(reader).map(SSHMsg::RequestFailure),
        MsgChannelOpen::MAGIC => MsgChannelOpen::read_ssh(reader).map(SSHMsg::ChannelOpen),
        MsgChannelOpenConfirmation::MAGIC => MsgChannelOpenConfirmation::read_ssh(reader).map(SSHMsg::ChannelOpenConfirmation),
        MsgChannelOpenFailure::MAGIC => MsgChannelOpenFailure::read_ssh(reader).map(SSHMsg::ChannelOpenFailure),
        MsgChannelWindowAdjust::MAGIC => MsgChannelWindowAdjust::read_ssh(reader).map(SSHMsg::ChannelWindowAdjust),
        MsgChannelData::MAGIC => MsgChannelData::read_ssh(reader).map(SSHMsg::ChannelData),
        MsgChannelExtendedData::MAGIC => MsgChannelExtendedData::read_ssh(reader).map(SSHMsg::ChannelExtendedData),
        MsgChannelEof::MAGIC => MsgChannelEof::read_ssh(reader).map(SSHMsg::ChannelEof),
        MsgChannelClose::MAGIC => MsgChannelClose::read_ssh(reader).map(SSHMsg::ChannelClose),
        MsgChannelRequest::MAGIC => MsgChannelRequest::read_ssh(reader).map(SSHMsg::ChannelRequest),
        MsgChannelSuccess::MAGIC => MsgChannelSuccess::read_ssh(reader).map(SSHMsg::ChannelSuccess),
        MsgChannelFailure::MAGIC => MsgChannelFailure::read_ssh(reader).map(SSHMsg::ChannelFailure),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Unknown magic number: {}", magic),
        )),
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
#[allow(dead_code)]
pub enum Magic {
    Disconnect = 1,               // byte       SSH_MSG_DISCONNECT
    Ignore = 2,                   // byte       SSH_MSG_IGNORE
    Unimplemented = 3,            // byte       SSH_MSG_UNIMPLEMENTED
    Debug = 4,                    // byte       SSH_MSG_DEBUG
    ServiceRequest = 5,           // byte       SSH_MSG_SERVICE_REQUEST
    ServiceAccept = 6,            // byte       SSH_MSG_SERVICE_ACCEPT
    KexInit = 20,                 // byte       SSH_MSG_KEXINIT
    NewKeys = 21,                 // byte       SSH_MSG_NEWKEYS
    KexECDHInit = 30,             // byte       SSH_MSG_KEX_ECDH_INIT (The client sends)
    KexECDHReply = 31,            // byte       SSH_MSG_KEX_ECDH_REPLY (The server responds with)
    UserauthRequest = 50,         // byte       SSH_MSG_USERAUTH_REQUEST
    UserauthFailure = 51,         // byte       SSH_MSG_USERAUTH_FAILURE
    UserauthSuccess = 52,         // byte       SSH_MSG_USERAUTH_SUCCESS
    UserauthBanner = 53,          // byte       SSH_MSG_USERAUTH_BANNER
    GlobalRequest = 80,           // byte       SSH_MSG_GLOBAL_REQUEST
    RequestSuccess = 81,          // byte       SSH_MSG_REQUEST_SUCCESS
    RequestFailure = 82,          // byte       SSH_MSG_REQUEST_FAILURE
    ChannelOpen = 90,             // byte       SSH_MSG_CHANNEL_OPEN
    ChannelOpenConfirmation = 91, // byte       SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    ChannelOpenFailure = 92,      // byte       SSH_MSG_CHANNEL_OPEN_FAILURE
    ChannelWindowAdjust = 93,     // byte       SSH_MSG_CHANNEL_WINDOW_ADJUST
    ChannelData = 94,             // byte       SSH_MSG_CHANNEL_DATA
    ChannelExtendedData = 95,     // byte       SSH_MSG_CHANNEL_EXTENDED_DATA
    ChannelEof = 96,              // byte       SSH_MSG_CHANNEL_EOF
    ChannelClose = 97,            // byte       SSH_MSG_CHANNEL_CLOSE
    ChannelRequest = 98,          // byte       SSH_MSG_CHANNEL_REQUEST
    ChannelSuccess = 99,          // byte       SSH_MSG_CHANNEL_SUCCESS
    ChannelFailure = 100,         // byte       SSH_MSG_CHANNEL_FAILURE
}

// Enums
#[repr(u32)] // RFC 4250 says reason code is uint32
#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone, Copy)] // Added Clone, Copy
pub enum DisconnectCode {
    HostNotAllowedToConnect = 1,     // SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT
    ProtocolError = 2,               // SSH_DISCONNECT_PROTOCOL_ERROR
    KeyExchangeFailed = 3,           // SSH_DISCONNECT_KEY_EXCHANGE_FAILED
    Reserved = 4,                    // SSH_DISCONNECT_RESERVED
    MacError = 5,                    // SSH_DISCONNECT_MAC_ERROR
    CompressionError = 6,            // SSH_DISCONNECT_COMPRESSION_ERROR
    ServiceNotAvailable = 7,         // SSH_DISCONNECT_SERVICE_NOT_AVAILABLE
    ProtocolVersionNotSupported = 8, // SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED
    HostKeyNotVerifiable = 9,        // SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE
    ConnectionLost = 10,             // SSH_DISCONNECT_CONNECTION_LOST
    ByApplication = 11,              // SSH_DISCONNECT_BY_APPLICATION
    TooManyConnections = 12,         // SSH_DISCONNECT_TOO_MANY_CONNECTIONS
    AuthCancelledByUser = 13,        // SSH_DISCONNECT_AUTH_CANCELLED_BY_USER
    NoMoreAuthMethodsAvailable = 14, // SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE
    IllegalUserName = 15,            // SSH_DISCONNECT_ILLEGAL_USER_NAME
}

#[repr(u32)] // RFC 4250 says reason code is uint32
#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone, Copy)] // Added Clone, Copy
pub enum ChannelOpenFailureReasonCode {
    AdministrativelyProhibited = 1, // SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
    ConnectFailed = 2,              // SSH_OPEN_CONNECT_FAILED
    UnknownChannelType = 3,         // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
    ResourceShortage = 4,           // SSH_OPEN_RESOURCE_SHORTAGE
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone, Copy)] // Added Clone, Copy
#[allow(non_camel_case_types, non_snake_case)]
pub enum PseudoTerminalModes {
    TTY_OP_END = 0,      // Indicates end of options.
    VINTR = 1,           // Interrupt character; 255 if none.  Similarly for the other characters.
    VQUIT = 2,           // The quit character (sends SIGQUIT signal on POSIX systems).
    VERASE = 3,          // Erase the character to left of the cursor.
    VKILL = 4,           // Kill the current input line.
    VEOF = 5,            // End-of-file character (sends EOF from the terminal).
    VEOL = 6,            // End-of-line character in addition to carriage return and/or linefeed.
    VEOL2 = 7,           // Additional end-of-line character.
    VSTART = 8,          // Continues paused output (normally control-Q).
    VSTOP = 9,           // Pauses output (normally control-S).
    VSUSP = 10,          // Suspends the current program.
    VDSUSP = 11,         // Another suspend character.
    VREPRINT = 12,       // Reprints the current input line.
    VWERASE = 13,        // Erases a word left of cursor.
    VLNEXT = 14, // Enter the next character typed literally, even if it is a special character.
    VFLUSH = 15, // Character to flush output.
    VSWTCH = 16, // Switch to a different shell layer.
    VSTATUS = 17, // Prints system status line (load, command, pid, etc).
    VDISCARD = 18, // Toggles the flushing of terminal output.
    IGNPAR = 30, // The ignore parity flag. The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is TRUE.
    PARMRK = 31, // Mark parity and framing errors.
    INPCK = 32,  // Enable checking of parity errors.
    ISTRIP = 33, // Strip 8th bit off characters.
    INLCR = 34,  // Map NL into CR on input.
    IGNCR = 35,  // Ignore CR on input.
    ICRNL = 36,  // Map CR to NL on input.
    IUCLC = 37,  // Translate uppercase characters to lowercase.
    IXON = 38,   // Enable output flow control.
    IXANY = 39,  // Any char will restart after stop.
    IXOFF = 40,  // Enable input flow control.
    IMAXBEL = 41, // Ring bell on input queue full.
    ISIG = 50,   // Enable signals INTR, QUIT, [D]SUSP.
    ICANON = 51, // Canonicalize input lines.
    XCASE = 52, // Enable input and output of uppercase characters by preceding their lowercase equivalents with "\".
    ECHO = 53,  // Enable echoing.
    ECHOE = 54, // Visually erase chars.
    ECHOK = 55, // Kill character discards current line.
    ECHONL = 56, // Echo NL even if ECHO is off.
    NOFLSH = 57, // Don't flush after interrupt.
    TOSTOP = 58, // Stop background jobs from output.
    IEXTEN = 59, // Enable extensions.
    ECHOCTL = 60, // Echo control characters as (Char).
    ECHOKE = 61, // Visual erase for line kill.
    PENDIN = 62, // Retype pending input.
    OPOST = 70, // Enable output processing.
    OLCUC = 71, // Convert lowercase to uppercase.
    ONLCR = 72, // Map NL to CR-NL.
    OCRNL = 73, // Translate carriage return to newline (output).
    ONOCR = 74, // Translate newline to carriage return-newline (output).
    ONLRET = 75, // Newline performs a carriage return (output).
    CS7 = 90,   // 7 bit mode.
    CS8 = 91,   // 8 bit mode.
    PARENB = 92, // Parity enable.
    PARODD = 93, // Odd parity, else even.
    TTY_OP_ISPEED = 128, // Specifies the input baud rate in bits per second.
    TTY_OP_OSPEED = 129, // Specifies the output baud rate in bits per second.
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
#[allow(non_camel_case_types, non_snake_case)]
pub enum Service {
    ssh__userauth,
    ssh__connection,
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
#[allow(non_camel_case_types, non_snake_case)]
pub enum AuthenticationMethod {
    publickey,
    password,
    hostBased,
    none,
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
#[allow(non_camel_case_types, non_snake_case)]
pub enum ConnectionProtocolChannelType {
    session,
    x11,
    forwarded__tcpip,
    direct__tcpip,
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
#[allow(non_camel_case_types, non_snake_case)]
pub enum ConnectionProtocolRequestType {
    tcpip__forward,
    cancel__tcpip__forward,
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
#[allow(non_camel_case_types, non_snake_case)]
pub enum ConnectionProtocolChannelRequestName {
    pty__req,
    x11__req,
    env,
    shell,
    exec,
    subsystem,
    window__change,
    xon__xoff,
    signal,
    exit__status,
    exit__signal,
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone, Copy)] // Added Clone, Copy
#[allow(non_camel_case_types, non_snake_case)]
pub enum SignalName {
    ABRT,
    ALRM,
    FPE,
    HUP,
    ILL,
    INT,
    KILL,
    PIPE,
    QUIT,
    SEGV,
    TERM,
    USR1,
    USR2,
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
#[allow(non_camel_case_types, non_snake_case)]
pub enum KeyExchangeMethod {
    ecdh__sha2__nistp256,
    Unknown(String),
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
#[allow(non_camel_case_types, non_snake_case)]
pub enum EncryptionAlgorithm {
    aes128__ctr,
    none,
    Unknown(String),
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
#[allow(non_camel_case_types, non_snake_case)]
pub enum MACAlgorithm {
    hmac__sha1,
    hmac__sha2__256,
    none,
    Unknown(String),
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
#[allow(non_camel_case_types, non_snake_case)]
pub enum PublicKeyAlgorithm {
    ssh__rsa,
    ssh__ed25519,
    Unknown(String),
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
#[allow(non_camel_case_types, non_snake_case)]
pub enum CompressionAlgorithm {
    zlib,
    none,
    Unknown(String),
}

// Structs
#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
pub struct MsgDisconnect {
    pub code: DisconnectCode, // uint32    reason code
    pub description: String,  // string    description in ISO__10646 UTF__8 encoding [RFC3629]
    pub language: String,     // string    language tag [RFC3066]
}

impl SSHMagic for MsgDisconnect {
    const MAGIC: u8 = Magic::Disconnect as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
pub struct MsgIgnore {
    pub data: String, // string    data
}

impl SSHMagic for MsgIgnore {
    const MAGIC: u8 = Magic::Ignore as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
pub struct MsgUnimplemented {
    pub packet_sequence_number: u32, // uint32    packet sequence number of rejected message
}

impl SSHMagic for MsgUnimplemented {
    const MAGIC: u8 = Magic::Unimplemented as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
pub struct MsgDebug {
    pub always_display: bool, // boolean   always_display
    pub message: String,      // string    message in ISO__10646 UTF__8 encoding [RFC3629]
    pub language: String,     // string    language tag [RFC3066]
}

impl SSHMagic for MsgDebug {
    const MAGIC: u8 = Magic::Debug as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgServiceRequest {
    pub service_name: String, // string    service name
}

impl SSHMagic for MsgServiceRequest {
    const MAGIC: u8 = Magic::ServiceRequest as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgServiceAccept {
    pub service_name: String, // string    service name
}

impl SSHMagic for MsgServiceAccept {
    const MAGIC: u8 = Magic::ServiceAccept as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone)] // Added Clone
pub struct MsgKexInit {
    pub cookie: [u8; 16],            // byte[16]     cookie (random bytes)
    pub kex_algorithms: Vec<String>, // name-list    kex_algorithms
    pub server_host_key_algorithms: Vec<String>, // name-list    server_host_key_algorithms
    pub encryption_algorithms_client_to_server: Vec<String>, // name-list    encryption_algorithms_client_to_server
    pub encryption_algorithms_server_to_client: Vec<String>, // name-list    encryption_algorithms_server_to_client
    pub mac_algorithms_client_to_server: Vec<String>, // name-list    mac_algorithms_client_to_server
    pub mac_algorithms_server_to_client: Vec<String>, // name-list    mac_algorithms_server_to_client
    pub compression_algorithms_client_to_server: Vec<String>, // name-list    compression_algorithms_client_to_server
    pub compression_algorithms_server_to_client: Vec<String>, // name-list    compression_algorithms_server_to_client
    pub languages_client_to_server: Vec<String>, // name-list    languages_client_to_server
    pub languages_server_to_client: Vec<String>, // name-list    languages_server_to_client
    pub kex_first_packet_follows: bool,          // boolean      first_kex_packet_follows
    pub reserved: u32,                           // uint32       0 (reserved for future extension)
}

impl SSHMagic for MsgKexInit {
    const MAGIC: u8 = Magic::KexInit as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH, Clone, Copy)] // Added Clone, Copy
pub struct MsgNewKeys {}

impl SSHMagic for MsgNewKeys {
    const MAGIC: u8 = Magic::NewKeys as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgKexECDHInit {
    pub q_c: Vec<u8>, // string   Q_C, client's ephemeral public key octet string
}

impl SSHMagic for MsgKexECDHInit {
    const MAGIC: u8 = Magic::KexECDHInit as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgKexECDHReply {
    pub k_s: Vec<u8>,       // string   K_S, server's public host key
    pub q_s: Vec<u8>,       // string   Q_S, server's ephemeral public key octet string
    pub signature: Vec<u8>, // string   the signature on the exchange hash
}

impl SSHMagic for MsgKexECDHReply {
    const MAGIC: u8 = Magic::KexECDHReply as u8;
}

// User Authentication Protocol Messages (RFC 4252)

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgUserauthRequest {
    pub user_name: String,
    pub service_name: String,
    pub method_name: String,
    // Method-specific fields will be read manually
}
impl SSHMagic for MsgUserauthRequest {
    const MAGIC: u8 = Magic::UserauthRequest as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgUserauthFailure {
    pub authentications_that_can_continue: Vec<String>,
    pub partial_success: bool,
}
impl SSHMagic for MsgUserauthFailure {
    const MAGIC: u8 = Magic::UserauthFailure as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgUserauthSuccess {}
impl SSHMagic for MsgUserauthSuccess {
    const MAGIC: u8 = Magic::UserauthSuccess as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgUserauthBanner {
    pub message: String,
    pub language_tag: String,
}
impl SSHMagic for MsgUserauthBanner {
    const MAGIC: u8 = Magic::UserauthBanner as u8;
}

// Connection Protocol Messages (RFC 4254)

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgGlobalRequest { // Placeholder
    pub request_name: String,
    pub want_reply: bool,
    // Request-specific data omitted for now
}
impl SSHMagic for MsgGlobalRequest {
    const MAGIC: u8 = Magic::GlobalRequest as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgRequestSuccess { // Placeholder
    // Port number for tcpip-forward, or other request-specific data
    pub data: Vec<u8>,
}
impl SSHMagic for MsgRequestSuccess {
    const MAGIC: u8 = Magic::RequestSuccess as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgRequestFailure { // Placeholder
    // No fields for this message as per RFC 4254, Section 4
}
impl SSHMagic for MsgRequestFailure {
    const MAGIC: u8 = Magic::RequestFailure as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelOpen { // Placeholder
    pub channel_type: String, // "session", "x11", "forwarded-tcpip", "direct-tcpip"
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
    // Type-specific data omitted for now
}
impl SSHMagic for MsgChannelOpen {
    const MAGIC: u8 = Magic::ChannelOpen as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelOpenConfirmation { // Placeholder
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
    // Type-specific data omitted for now
}
impl SSHMagic for MsgChannelOpenConfirmation {
    const MAGIC: u8 = Magic::ChannelOpenConfirmation as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelOpenFailure { // Placeholder
    pub recipient_channel: u32,
    pub reason_code: ChannelOpenFailureReasonCode,
    pub description: String,
    pub language_tag: String,
}
impl SSHMagic for MsgChannelOpenFailure {
    const MAGIC: u8 = Magic::ChannelOpenFailure as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelWindowAdjust { // Placeholder
    pub recipient_channel: u32,
    pub bytes_to_add: u32,
}
impl SSHMagic for MsgChannelWindowAdjust {
    const MAGIC: u8 = Magic::ChannelWindowAdjust as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelData { // Placeholder
    pub recipient_channel: u32,
    pub data: Vec<u8>,
}
impl SSHMagic for MsgChannelData {
    const MAGIC: u8 = Magic::ChannelData as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelExtendedData { // Placeholder
    pub recipient_channel: u32,
    pub data_type_code: u32, // e.g., SSH_EXTENDED_DATA_STDERR (1)
    pub data: Vec<u8>, // Changed from String
}
impl SSHMagic for MsgChannelExtendedData {
    const MAGIC: u8 = Magic::ChannelExtendedData as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelEof { // Placeholder
    pub recipient_channel: u32,
}
impl SSHMagic for MsgChannelEof {
    const MAGIC: u8 = Magic::ChannelEof as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelClose { // Placeholder
    pub recipient_channel: u32,
}
impl SSHMagic for MsgChannelClose {
    const MAGIC: u8 = Magic::ChannelClose as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelRequest { // Placeholder
    pub recipient_channel: u32,
    pub request_type: String, // e.g., "pty-req", "shell", "exit-status"
    pub want_reply: bool,
    // Type-specific data omitted for now
}
impl SSHMagic for MsgChannelRequest {
    const MAGIC: u8 = Magic::ChannelRequest as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelSuccess { // Placeholder
    pub recipient_channel: u32,
}
impl SSHMagic for MsgChannelSuccess {
    const MAGIC: u8 = Magic::ChannelSuccess as u8;
}

#[derive(Debug, PartialEq, ReadSSH, WriteSSH)]
pub struct MsgChannelFailure { // Placeholder
    pub recipient_channel: u32,
}
impl SSHMagic for MsgChannelFailure {
    const MAGIC: u8 = Magic::ChannelFailure as u8;
}


#[derive(Debug, PartialEq)]
#[allow(dead_code)]
pub enum SSHMsg {
    Disconnect(MsgDisconnect),
    Ignore(MsgIgnore),
    Unimplemented(MsgUnimplemented),
    Debug(MsgDebug),
    ServiceRequest(MsgServiceRequest),
    ServiceAccept(MsgServiceAccept),
    KexInit(MsgKexInit),
    NewKeys(MsgNewKeys),
    KexECDHInit(MsgKexECDHInit),
    KexECDHReply(MsgKexECDHReply),
    UserauthRequest(MsgUserauthRequest),
    UserauthFailure(MsgUserauthFailure),
    UserauthSuccess(MsgUserauthSuccess),
    UserauthBanner(MsgUserauthBanner),
    GlobalRequest(MsgGlobalRequest),
    RequestSuccess(MsgRequestSuccess),
    RequestFailure(MsgRequestFailure),
    ChannelOpen(MsgChannelOpen),
    ChannelOpenConfirmation(MsgChannelOpenConfirmation),
    ChannelOpenFailure(MsgChannelOpenFailure),
    ChannelWindowAdjust(MsgChannelWindowAdjust),
    ChannelData(MsgChannelData),
    ChannelExtendedData(MsgChannelExtendedData),
    ChannelEof(MsgChannelEof),
    ChannelClose(MsgChannelClose),
    ChannelRequest(MsgChannelRequest),
    ChannelSuccess(MsgChannelSuccess),
    ChannelFailure(MsgChannelFailure),
}