package in.vojt.loonyssh

import com.jcraft.jsch.jce.AES128CTR
import com.jcraft.jsch.ExposedBuffer
import com.jcraft.jsch.jce.HMACSHA1

import java.util.Locale
import scala.compiletime.constValue
import scala.compiletime.erasedValue

trait SSHMsg[M <: Int](val magic: M)

object SSHMsg:

    inline def magic[S <: SSHMsg[?]]: Int = inline erasedValue[S] match {
        case _: SSHMsg[t] => constValue[t]
        case _ => -1
    }

    /**
     * https://tools.ietf.org/html/rfc4250#section-4.1.2
     */
    object Magic:
        type Disconnect = 1
        type Ignore = 2
        type Unimplemented = 3
        type Debug = 4
        type ServiceRequest = 5
        type ServiceAccept = 6
        type KexInit = 20
        type NewKeys = 21
        type KexECDHInit = 30
        type KexECDHReply = 31
        type UserauthRequest = 50
        type UserauthFailure = 51
        type UserauthSuccess = 52
        type UserauthBanner = 53
        type GlobalRequest = 80
        type RequestSuccess = 81
        type RequestFailure = 82
        type ChannelOpen = 90
        type ChannelOpenConfirmation = 91
        type ChannelOpenFailure = 92
        type ChannelWindowAdjust = 93
        type ChannelData = 94
        type ChannelExtendedData = 95
        type ChannelEof = 96
        type ChannelClose = 97
        type ChannelRequest = 98
        type ChannelSuccess = 99
        type ChannelFailure = 100

    /**
     * byte      SSH_MSG_DISCONNECT
     * uint32    reason code
     * string    description in ISO-10646 UTF-8 encoding [RFC3629]
     * string    language tag [RFC3066]
     */
    case class Disconnect(code: DisconnectCode, description: String, language: Locale) extends SSHMsg[Magic.Disconnect](constValue)

    /**
     * byte      SSH_MSG_IGNORE
     * string    data
     */
    case class Ignore(data: String) extends SSHMsg[Magic.Ignore](constValue)

    /**
     * byte      SSH_MSG_UNIMPLEMENTED
     * uint32    packet sequence number of rejected message
     */
    case class Unimplemented(packetSequenceNumber: Int) extends SSHMsg[Magic.Unimplemented](constValue)

    /**
     * byte      SSH_MSG_DEBUG
     * boolean   always_display
     * string    message in ISO-10646 UTF-8 encoding [RFC3629]
     * string    language tag [RFC3066]
     */
    case class Debug(alwaysDisplay: Boolean,
                     message: String,
                     language: Locale,
                    ) extends SSHMsg[Magic.Debug](constValue)

    /**
     * byte      SSH_MSG_SERVICE_REQUEST
     * string    service name
     */
    case class ServiceRequest(serviceName: Service) extends SSHMsg[Magic.ServiceRequest](constValue)

    /**
     * byte      SSH_MSG_SERVICE_ACCEPT
     * string    service name
     */
    case class ServiceAccept(serviceName: Service) extends SSHMsg[Magic.ServiceAccept](constValue)

    /**
     * byte         SSH_MSG_KEXINIT
     * byte[16]     cookie (random bytes)
     * name-list    kex_algorithms
     * name-list    server_host_key_algorithms
     * name-list    encryption_algorithms_client_to_server
     * name-list    encryption_algorithms_server_to_clien
     * name-list    mac_algorithms_client_to_server
     * name-list    mac_algorithms_server_to_clien
     * name-list    compression_algorithms_client_to_server
     * name-list    compression_algorithms_server_to_clien
     * name-list    languages_client_to_server
     * name-list    languages_server_to_clien
     * boolean      first_kex_packet_follows
     * uint32       0 (reserved for future extension)
     */
    case class KexInit(
                        cookie: FixedSizeList[4, Int],
                        kexAlgorithms: NameList[KeyExchangeMethod],
                        serverHostKeyAlgorithms: NameList[PublicKeyAlgorithm],
                        encryptionAlgorithmsClientToServer: NameList[EncryptionAlgorithm],
                        encryptionAlgorithmsServerToClient: NameList[EncryptionAlgorithm],
                        macAlgorithmsClientToServer: NameList[MACAlgorithm],
                        macAlgorithmsServerToClient: NameList[MACAlgorithm],
                        compressionAlgorithmsClientToServer: NameList[CompressionAlgorithm],
                        compressionAlgorithmsServerToClient: NameList[CompressionAlgorithm],
                        languagesClientToServer: NameList[String],
                        languagesServerToClient: NameList[String],
                        kexFirstPacketFollows: Byte,
                        reserved: Int) extends SSHMsg[Magic.KexInit](constValue)

    /**
     * byte      SSH_MSG_NEWKEYS
     */
    case object NewKeys extends SSHMsg[Magic.NewKeys](constValue)

    /**
     * The client sends:
     *
     * byte     SSH_MSG_KEX_ECDH_INIT
     * string   Q_C, client's ephemeral public key octet string
     */
    case class KexECDHInit(Q_C: Seq[Byte]) extends SSHMsg[Magic.KexECDHInit](constValue)

    /**
     * The server responds with:
     *
     * byte     SSH_MSG_KEX_ECDH_REPLY
     * string   K_S, server's public host key
     * string   Q_S, server's ephemeral public key octet string
     * string   the signature on the exchange hash
     *
     * The exchange hash H is computed as the hash of the concatenation of
     * the following.
     *
     * string   V_C, client's identification string (CR and LF excluded)
     * string   V_S, server's identification string (CR and LF excluded)
     * string   I_C, payload of the client's SSH_MSG_KEXINIT
     * string   I_S, payload of the server's SSH_MSG_KEXINIT
     * string   K_S, server's public host key
     * string   Q_C, client's ephemeral public key octet string
     * string   Q_S, server's ephemeral public key octet string
     * mpint    K,   shared secret
     */
    case class KexECDHReply(kS: Array[Byte],
                            qS: Array[Byte],
                            signature: Array[Byte]) extends SSHMsg[Magic.KexECDHReply](constValue)


/**
 * - SSH-protoversion-softwareversion SP comments CR LF
 * - BinaryPacket
 */
enum Transport:
    case Identification(version: String)

    /**
     * uint32    packet_length
     * byte      padding_length
     * byte[n1]  payload; n1 = packet_length - padding_length - 1
     * byte[n2]  random padding; n2 = padding_length
     * byte[m]   mac (Message Authentication Code - MAC); m = mac_length
     */
    case BinaryPacket(len: Int,
                      pad: Byte,
                      magic: Byte,
                      payload: Array[Byte],
                      padding: Array[Byte])

    case EncryptedPacket(payload: Array[Byte],
                         mac: Array[Byte])

object Transport:
    def encrypt(packet: Transport.BinaryPacket)(using ctx: SSHContext): Transport.EncryptedPacket = ctx match
        case SSHContext(_, _, Some(cypherC2S), _, Some(macC2S), _) =>
            val mac = new Array[Byte](macC2S.getBlockSize)
            val buf = new ExposedBuffer()
            buf.putInt(packet.len)
            buf.putByte(packet.pad)
            buf.putByte(packet.magic)
            buf.putByte(packet.payload)
            buf.putByte(packet.padding)

            macC2S.update(SSHContext.seqo.get())
            macC2S.update(buf.getBuffer, 0, buf.getIndex)
            macC2S.doFinal(mac, 0)

            cypherC2S.update(buf.getBuffer, 0, buf.getIndex, buf.getBuffer, 0)

            new Transport.EncryptedPacket(buf.getBuffer.take(buf.getIndex), mac)


    def apply(magic: Byte, data: Array[Byte])(using ctx: SSHContext): Transport.BinaryPacket =
        val payloadSize = data.length + 1
        val blockSize = ctx.cypherC2SBlockSize
        // the extra 8 bytes can be for if in etm mode where packet size is not encrypted
        val paddingSize = (3 + blockSize - ((payloadSize + 8) % blockSize)).toByte
        val packetSize = payloadSize + paddingSize + 1

        new Transport.BinaryPacket(
            packetSize,
            paddingSize,
            magic,
            data,
            Array.fill(paddingSize)(8),
        )