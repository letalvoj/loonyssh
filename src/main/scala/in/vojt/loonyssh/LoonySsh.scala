package in.vojt.loonyshh

import java.net._
import java.io._
import scala.io.Source
import java.nio.ByteBuffer
import scala.compiletime.{constValue, summonInline, erasedValue, S}
import scala.reflect.ClassTag

import scala.deriving._

val IdentificationString = "SSH-2.0-loonySSH_0.0.1\r\n"

// trait SshProtocolIO:
//     def is: BufferedInputStream
//     def out: BufferedOutputStream

// trait SshWriter[V]:
//     def write(value:V, out: BufferedOutputStream): Unit
    // given SshWriter[Int]:
    //     def write(value:Int, out: BufferedOutputStream): Unit = out.write(ByteBuffer.allocate(4).putInt(value).array)

trait SshReader[V]: // reader monad?
    def read(is: BufferedInputStream): V // should be Either

    def map[W](f:V=>W):SshReader[W] = new SshReader[W]:
        def read(is: BufferedInputStream): W = f(SshReader.this.read(is))

    def flatMap[W](f:V=>SshReader[W]):SshReader[W] = new SshReader[W]:
        def read(is: BufferedInputStream): W = f(SshReader.this.read(is)).read(is)

case class LSeq[L<:Int, V](arr:Seq[V])

object SshReader:
    // type LTuple[Len<:Int,V] = _T[0,Len,V]
    // type _T[I,Len,V] <: Tuple = I match
    //     case Len => Unit
    //     case I => V *: _T[S[I],Len,V]

    inline def apply[V](using impl: SshReader[V]):SshReader[V] = impl

    inline given lSeq[L<:Int, T:ClassTag] as SshReader[LSeq[L,T]] = new SshReader:
        def read(is: BufferedInputStream): LSeq[L, T] = 
            LSeq(Array.fill(constValue[L])(summonInline[SshReader[T]].read(is)).toSeq)

    given intReader as SshReader[Int] = is => ByteBuffer.wrap(is.readNBytes(4)).getInt
    given byteReader as SshReader[Byte] = is => is.read().toByte

    inline def arrayReader(n:Int) = new SshReader[Array[Byte]]:
        def read(is: BufferedInputStream): Array[Byte] = is.readNBytes(n)

    given stringReader as SshReader[String] = for {
        n <- SshReader[Int]
        a <- arrayReader(n)
    } yield new String(a)

    inline given derived[V](using m: Mirror.ProductOf[V]) as SshReader[V] = new SshReader:
        def read(is: BufferedInputStream): V = 
            val parsed = readProduct[m.MirroredElemTypes](is)(0)
            m.fromProduct(parsed.asInstanceOf[Product]).asInstanceOf[V]
        
    inline private def readProduct[T](is: BufferedInputStream)(i:Int):Tuple = inline erasedValue[T] match
        case _: (t *: ts) => summonInline[SshReader[t]].read(is) *: readProduct[ts](is)(i+1)
        case _: Unit => ()

/**
    A string containing a comma-separated list of names.  A name-list
    is represented as a uint32 containing its length (number of bytes
    that follow) followed by a comma-separated list of zero or more
    names.  A name MUST have a non-zero length, and it MUST NOT
    contain a comma (",").  As this is a list of names, all of the
    elements contained are names and MUST be in US-ASCII.
*/
case class NameList(names:List[String])

object NameList:
    given reader as SshReader[NameList] = SshReader[String].map(s => NameList(s.split(",").toList))

object SSHMagic:
    type DISCONNECT       = 1
    type IGNORE           = 2
    type UNIMPLEMENTED    = 3
    type DEBUG            = 4
    type SERVICE_REQUEST  = 5
    type SERVICE_ACCEPT   = 6
    type NEWKEYS          = 21
    type KEXINIT          = 20

enum SSHMsg[M<:Int]:

    /**
        byte      SSH_MSG_DISCONNECT
        uint32    reason code
        string    description in ISO-10646 UTF-8 encoding [RFC3629]
        string    language tag [RFC3066]
    */
    case Disconnect(code: DisconnectCode, description: String, language: String) extends SSHMsg[1]

    /**
        byte      SSH_MSG_IGNORE
        string    data
    */
    case Ignore(data:String)          extends SSHMsg[2]

    /**
        byte      SSH_MSG_UNIMPLEMENTED
        uint32    packet sequence number of rejected message
    */
    case Unimplemented(packetSequenceNumber:Int) extends SSHMsg[3]

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
    ) extends SSHMsg[4]

    /**
        byte      SSH_MSG_SERVICE_REQUEST
        string    service name
    */
    case ServiceRequest(serviceName: String) extends SSHMsg[5]

    /**
        byte      SSH_MSG_SERVICE_ACCEPT
        string    service name
    */
    case ServiceAccept(serviceName: String) extends SSHMsg[6]

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
        kexAlgorithms: NameList,
        serverHostKeyAlgorithms: NameList,
        encryptionAlgorithmsClientToServer: NameList,
        encryptionAlgorithmsServerToClient: NameList,
        macAlgorithmsClientToServer: NameList,
        macAlgorithmsServerToClient: NameList,
        compressionAlgorithmsClientToServer: NameList,
        compressionAlgorithmsServerToClient: NameList,
        languagesClientToServer: NameList,
        languagesServerToClient: NameList,
        kexFirstPacketFollows: Byte,
        reserved: Int) extends SSHMsg[20]

    /**
        byte      SSH_MSG_NEWKEYS
    */
    case NewKeys extends SSHMsg[21]


enum DisconnectCode(val code:Int):
    case HostNotAllowedToConnect     extends DisconnectCode(1)
    case ProtocolError               extends DisconnectCode(2)
    case KeyExchangeFailed           extends DisconnectCode(3)
    case Reserved                    extends DisconnectCode(4)
    case MacError                    extends DisconnectCode(5)
    case CompressionError            extends DisconnectCode(6)
    case ServiceNotAvailable         extends DisconnectCode(7)
    case ProtocolVersionNotSupported extends DisconnectCode(8)
    case HostKeyNotVerifiable        extends DisconnectCode(9)
    case ConnectionLost              extends DisconnectCode(10)
    case ByApplication               extends DisconnectCode(11)
    case TooManyConnections          extends DisconnectCode(12)
    case AuthCancelledByUser         extends DisconnectCode(13)
    case NoMoreAuthMethodsAvailable  extends DisconnectCode(14)
    case IllegalUserName             extends DisconnectCode(15)

    val ByCode = DisconnectCode.values.map(obj => (obj.code, obj)).toMap
    given reader as SshReader[DisconnectCode] = SshReader[Int].map(ByCode(_))

/**
      uint32    packet_length
      byte      padding_length
      byte[n1]  payload; n1 = packet_length - padding_length - 1
      byte[n2]  random padding; n2 = padding_length
      byte[m]   mac (Message Authentication Code - MAC); m = mac_length
*/
case class Envelope[V](length:Int, paddingLength:Int, payload:V, mac:Array[Byte])

@main def loonymain():Unit =
    val socket = new Socket("172.16.70.12", 22)

    val inStr = new BufferedInputStream(socket.getInputStream)
    val outStr = socket.getOutputStream
    
    outStr.write(IdentificationString.getBytes)
    outStr.flush

    println("yay!")
    LazyList.continually(inStr.read).map{
        case c if c < 128  => c.toChar
        case _ => '�'
    }.takeWhile(_ != '\n').foreach(print)
    inStr.read

    inStr.readNBytes(4).toSeq // shrug
    inStr.readNBytes(1).toSeq // magic
    // inStr.readNBytes(16).toSeq // random

    println(summon[SshReader[SSHMsg.KexInit]].read(inStr))

    println(LazyList.continually(inStr.read).takeWhile(_ => inStr.available() > 0).toList)

    // println("\ndone!")

    // println(Envelope(inStr))

    outStr.flush
    socket.close
