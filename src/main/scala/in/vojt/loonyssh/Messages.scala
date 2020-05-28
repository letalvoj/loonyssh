package in.vojt.loonyshh

import in.vojt.loonyshh.names._

/**
    https://tools.ietf.org/html/rfc4250#section-4.1.2
*/
object Magic:
    val Disconnect              =   1
    val Ignore                  =   2
    val Unimplemented           =   3
    val Debug                   =   4
    val ServiceRequest          =   5
    val ServiceAccept           =   6
    val KexInit                 =  20
    val NewKeys                 =  21
    val UserauthRequest         =  50
    val UserauthFailure         =  51
    val UserauthSuccess         =  52
    val UserauthBanner          =  53
    val GlobalRequest           =  80
    val RequestSuccess          =  81
    val RequestFailure          =  82
    val ChannelOpen             =  90
    val ChannelOpenConfirmation =  91
    val ChannelOpenFailure      =  92
    val ChannelWindowAdjust     =  93
    val ChannelData             =  94
    val ChannelExtendedData     =  95
    val ChannelEof              =  96
    val ChannelClose            =  97
    val ChannelRequest          =  98
    val ChannelSuccess          =  99
    val ChannelFailure          = 100

enum SSHMsg(val magic:Int):


    /**
        byte      SSH_MSG_DISCONNECT
        uint32    reason code
        string    description in ISO-10646 UTF-8 encoding [RFC3629]
        string    language tag [RFC3066]
    */
    case Disconnect(code: DisconnectCode, description: String, language: String) extends SSHMsg(Magic.Disconnect)

    /**
        byte      SSH_MSG_IGNORE
        string    data
    */
    case Ignore(data:String)          extends SSHMsg(Magic.Ignore)

    /**
        byte      SSH_MSG_UNIMPLEMENTED
        uint32    packet sequence number of rejected message
    */
    case Unimplemented(packetSequenceNumber:Int) extends SSHMsg(Magic.Unimplemented)

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
    ) extends SSHMsg(Magic.Debug)

    /**
        byte      SSH_MSG_SERVICE_REQUEST
        string    service name
    */
    case ServiceRequest(serviceName: String) extends SSHMsg(Magic.ServiceRequest)

    /**
        byte      SSH_MSG_SERVICE_ACCEPT
        string    service name
    */
    case ServiceAccept(serviceName: String) extends SSHMsg(Magic.ServiceAccept)

    /**
        byte         SSH_MSG_KEXINIT
        byte[16]     cookie (random bytes)
        name-list    kex_algorithms
        name-list    server_host_key_algorithms
        name-list    encryption_algorithms_client_to_server
        name-list    encryption_algorithms_server_to_clien
        name-list    mac_algorithms_client_to_server
        name-list    mac_algorithms_server_to_clien
        name-list    compression_algorithms_client_to_server
        name-list    compression_algorithms_server_to_clien
        name-list    languages_client_to_server
        name-list    languages_server_to_clien
        boolean      first_kex_packet_follows
        uint32       0 (reserved for future extension)
    */
    case KexInit(
        cookie: LSeq[16,Byte],
        kexAlgorithms: NameList[String],
        serverHostKeyAlgorithms: NameList[String],
        encryptionAlgorithmsClientToServer: NameList[String],
        encryptionAlgorithmsServerToClient: NameList[String],
        macAlgorithmsClientToServer: NameList[String],
        macAlgorithmsServerToClient: NameList[String],
        compressionAlgorithmsClientToServer: NameList[String],
        compressionAlgorithmsServerToClient: NameList[String],
        languagesClientToServer: NameList[String],
        languagesServerToClient: NameList[String],
        kexFirstPacketFollows: Byte,
        reserved: Int) extends SSHMsg(Magic.KexInit)

    /**
        byte      SSH_MSG_NEWKEYS
    */
    case NewKeys extends SSHMsg(Magic.NewKeys)

/**
      uint32    packet_length
      byte      padding_length
      byte[n1]  payload; n1 = packet_length - padding_length - 1
      byte[n2]  random padding; n2 = padding_length
      byte[m]   mac (Message Authentication Code - MAC); m = mac_length
*/
case class Envelope[V](length:Int, paddingLength:Byte, payload:V, mac:Array[Byte])
