package in.vojt.loonyshh

/**
    https://tools.ietf.org/html/rfc4250#section-4.1.2
*/    
object Magic:
    type Disconnect              =   1
    type Ignore                  =   2
    type Unimplemented           =   3
    type Debug                   =   4
    type ServiceRequest          =   5
    type ServiceAccept           =   6
    type KexInit                 =  20
    type NewKeys                 =  21
    type UserauthRequest         =  50
    type UserauthFailure         =  51
    type UserauthSuccess         =  52
    type UserauthBanner          =  53
    type GlobalRequest           =  80
    type RequestSuccess          =  81
    type RequestFailure          =  82
    type ChannelOpen             =  90
    type ChannelOpenConfirmation =  91
    type ChannelOpenFailure      =  92
    type ChannelWindowAdjust     =  93
    type ChannelData             =  94
    type ChannelExtendedData     =  95
    type ChannelEof              =  96
    type ChannelClose            =  97
    type ChannelRequest          =  98
    type ChannelSuccess          =  99
    type ChannelFailure          = 100

enum SSHMsg[M<:Int]:

    /**
        byte      SSH_MSG_DISCONNECT
        uint32    reason code
        string    description in ISO-10646 UTF-8 encoding [RFC3629]
        string    language tag [RFC3066]
    */
    case Disconnect(code: DisconnectCode, description: String, language: String) extends SSHMsg[Magic.Disconnect]

    /**
        byte      SSH_MSG_IGNORE
        string    data
    */
    case Ignore(data:String)          extends SSHMsg[Magic.Ignore]

    /**
        byte      SSH_MSG_UNIMPLEMENTED
        uint32    packet sequence number of rejected message
    */
    case Unimplemented(packetSequenceNumber:Int) extends SSHMsg[Magic.Unimplemented]

    /**
        byte      SSH_MSG_DEBUG
        boolean   always_display
        string    message in ISO-10646 UTF-8 encoding [RFC3629]
        string    language tag [RFC3066]
    */
    case Debug(
        alwaysDisplay: Boolean,
        message: String,
        language: String,
    ) extends SSHMsg[Magic.Debug]

    /**
        byte      SSH_MSG_SERVICE_REQUEST
        string    service name
    */
    case ServiceRequest(serviceName: String) extends SSHMsg[Magic.ServiceRequest]

    /**
        byte      SSH_MSG_SERVICE_ACCEPT
        string    service name
    */
    case ServiceAccept(serviceName: String) extends SSHMsg[Magic.ServiceAccept]

    /**
        byte         SSH_MSG_KEXINIT
        byte[16]     cookie (random bytes)
        name-list    kex_algorithms
        name-list    server_host_key_algorithms
        name-list    encryption_algorithms_client_to_server
        name-list    encryption_algorithms_server_to_client
        name-list    mac_algorithms_client_to_server
        name-list    mac_algorithms_server_to_client
        name-list    compression_algorithms_client_to_server
        name-list    compression_algorithms_server_to_client
        name-list    languages_client_to_server
        name-list    languages_server_to_client
        boolean      first_kex_packet_follows
        uint32       0 (reserved for future extension)
    */
    case KexInit(
        cookie: LSeq[16,Byte],
        kexAlgorithms: PlainNameList,
        serverHostKeyAlgorithms: PlainNameList,
        encryptionAlgorithmsClientToServer: PlainNameList,
        encryptionAlgorithmsServerToClient: PlainNameList,
        macAlgorithmsClientToServer: PlainNameList,
        macAlgorithmsServerToClient: PlainNameList,
        compressionAlgorithmsClientToServer: PlainNameList,
        compressionAlgorithmsServerToClient: PlainNameList,
        languagesClientToServer: PlainNameList,
        languagesServerToClient: PlainNameList,
        kexFirstPacketFollows: Byte,
        reserved: Int) extends SSHMsg[Magic.KexInit]

    /**
        byte      SSH_MSG_NEWKEYS
    */
    case NewKeys extends SSHMsg[Magic.NewKeys]

/**
      uint32    packet_length
      byte      padding_length
      byte[n1]  payload; n1 = packet_length - padding_length - 1
      byte[n2]  random padding; n2 = padding_length
      byte[m]   mac (Message Authentication Code - MAC); m = mac_length
*/
case class Envelope[V](length:Int, paddingLength:Int, payload:V, mac:Array[Byte])