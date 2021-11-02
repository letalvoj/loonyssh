package in.vojt.loonyssh

import com.jcraft.jsch.jce.SHA256
import com.jcraft.jsch.Buffer
import com.jcraft.jsch.Exposed

import java.awt.Font
import java.net.*
import java.io.*
import scala.io.Source
import java.nio.ByteBuffer
import scala.deriving.*
import scala.compiletime.*
import scala.reflect.ClassTag
import java.util.Random
// import scala.deriving.constValue
import com.jcraft.jsch.jce.ECDHN
import com.jcraft.jsch.DHEC256
import com.jcraft.jsch.DHECN
import com.jcraft.jsch.jce.SHA256
import com.jcraft.jsch.jce.SignatureRSA

val ClientName = "LoonySSH"
val ClientVersion = "0.0.1"
val IdentificationString = s"SSH-2.0-${ClientName}_${ClientVersion}\r\n"

def kexClient() = SSHMsg.KexInit(
    cookie = FixedSizeList[4, Int](List.fill(4)(4)),
    kexAlgorithms = NameList(List(KeyExchangeMethod.`ecdh-sha2-nistp256`)),
    serverHostKeyAlgorithms = NameList(List(PublicKeyAlgorithm.`ssh-rsa`)),
    encryptionAlgorithmsClientToServer = NameList(List(EncryptionAlgorithm.`aes128-ctr`)),
    encryptionAlgorithmsServerToClient = NameList(List(EncryptionAlgorithm.`aes128-ctr`)),
    macAlgorithmsClientToServer = NameList(List(MACAlgorithm.`hmac-sha1`)),
    macAlgorithmsServerToClient = NameList(List(MACAlgorithm.`hmac-sha1`)),
    compressionAlgorithmsClientToServer = NameList(List(CompressionAlgorithm.`none`)),
    compressionAlgorithmsServerToClient = NameList(List(CompressionAlgorithm.`none`)),
    languagesClientToServer = NameList(List()),
    languagesServerToClient = NameList(List()),
    kexFirstPacketFollows = 0,
    reserved = 0,
)

implicit val ctx: SSHContext = SSHContext()

def verify(H: Array[Byte], sig_of_H: Array[Byte]): SSHReader[Boolean] = for
    alg <- SSHReader[String]
    _ = assert(alg == "ssh-rsa")
    ee <- SSHReader[Array[Byte]]
    n <- SSHReader[Array[Byte]]
yield {
    val sig = new SignatureRSA()
    sig.init()
    sig.setPubKey(ee, n)
    sig.update(H)
    sig.verify(sig_of_H)
}

// replace as much jsch logic as possible with the JVM builtin cypher stuff

val sshProtocol: SSHReader[SSHMsg.KexECDHReply] = for
    vC <- SSHWriter.plain(new Transport.Identification(IdentificationString))
    vS <- SSHReader[Transport.Identification]
    bpKexClient <- SSHWriter.overBinaryProtocol(kexClient())
    (kexServer, bpKexServer) <- SSHReader.fromBinaryProtocol[SSHMsg.KexInit](mac = false)
    // TODO negotiate intead of assuming XDH / X25519
    (ecdh: ECDHN, qC: Array[Byte]) <- {
        // https://datatracker.ietf.org/doc/html/rfc5656#section-4

        val ecdh = new ECDHN()
        ecdh.init(256)
        val qC = ecdh.getQ

        SSHWriter.
          overBinaryProtocol(SSHMsg.KexECDHInit(qC)).
          map(_ => (ecdh, qC))
    }
    (ecdhReply, ecdhBp) <- SSHReader.fromBinaryProtocol[SSHMsg.KexECDHReply](mac = true)
    _ <- {
        val rs = Exposed.fromPoint(ecdhReply.qS)
        assert(ecdh.validate(rs(0), rs(1)))

        // DHECN.normalize
        // what the hell is the initial 0?
        val K = ecdh.getSecret(rs(0), rs(1))
        val sigofH = ecdhReply.signature
        val sha256 = new SHA256()
        sha256.init()

        val buf = new Buffer()
        buf.putString(vC.version.trim.getBytes) // string   V_C, client's identification string (CR and LF excluded)
        buf.putString(vS.version.trim.getBytes) // string   V_S, server's identification string (CR and LF excluded)
        buf.putString(Array(bpKexClient.magic) ++ bpKexClient.payload) // string   I_C, payload of the client's SSH_MSG_KEXINIT
        buf.putString(Array(bpKexServer.magic) ++ bpKexServer.payload) // string   I_S, payload of the server's SSH_MSG_KEXINIT
        buf.putString(ecdhReply.kS) // string   K_S, server's public host key
        buf.putString(qC) // string   Q_C, client's ephemeral public key octet string
        buf.putString(ecdhReply.qS) // string   Q_S, server's ephemeral public key octet string
        buf.putMPInt(K) // mpint    K__,   shared secret
        val foo = new Array[Byte](buf.getLength)
        buf.getByte(foo)
        sha256.update(foo, 0, foo.length)
        val H = sha256.digest

        verify(H, sigofH).read(BinaryProtocol(ByteBuffer.wrap(ecdhReply.kS))) match {
            case Right(true) =>
            case _ => throw RuntimeException("Failed to verify kex")
        }
        SSHWriter.overBinaryProtocol(SSHMsg.NewKeys)
    }
    //    _ <- SSHReader.fromBinaryProtocol[SSHMsg.NewKeys.type](mac = false)
yield
    ecdhReply

def negotiate(server: SSHMsg.KexInit, client: SSHMsg.KexInit): SSHMsg.KexInit =
    val kexAlgorithm = client.kexAlgorithms.find(client.kexAlgorithms.contains)
    ???


def connect(bis: BufferedInputStream, bos: BufferedOutputStream) =
    val errOrRes = sshProtocol.read(BinaryProtocol(bis, bos))
    errOrRes match {
        case Right(res) => println(s"RESULT: $res")
        case Left(Err.Exc(e)) => throw e
        case Left(o) => System.err.println(o)
    }

    //  import com.jcraft.jsch.jce.AES128CTR
    //  import com.jcraft.jsch.{DHEC256, Utils, WrapperIO, WrapperSession}
    //  val dh = new DHEC256(ident.getBytes, IdentificationString.getBytes, ???, ???)
    //  dh.init(sess)

    println("Remaining:")
    LazyList.continually(bis.read).
      map(c => f"${c}%02X-").
      take(30).
      foreach(print)

    println("Finished!")


@main def Main(): Unit =
    val soc = new Socket("localhost", 2200)

    val bis = new BufferedInputStream(soc.getInputStream)
    val bos = new BufferedOutputStream(soc.getOutputStream)

    try
        connect(bis, bos)
    finally
        bos.flush()
        soc.close()