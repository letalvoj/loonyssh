package in.vojt.loonyssh

import java.net.*
import java.io.*
import scala.io.Source
import java.nio.ByteBuffer
import scala.deriving.*
import scala.compiletime.*
import scala.reflect.ClassTag
import java.util.Random
// import scala.deriving.constValue

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

val sshProtocol = for
    _ <- SSHWriter.plain(new Transport.Identification(IdentificationString))
    sIs <- SSHReader[Transport.Identification]
    bpKexClient <- SSHWriter.overBinaryProtocol(kexClient())
    (kexServer, bpKexServer) <- SSHReader.fromBinaryProtocol[SSHMsg.KexInit](mac = false)
    _ = println(kexServer)
    // TODO negotiate intead of assuming XDH / X25519
    _ <- {
        // https://datatracker.ietf.org/doc/html/rfc5656#section-4

        import com.jcraft.jsch.jce.ECDHN
        import com.jcraft.jsch.jce.SHA256
        import com.jcraft.jsch.DHEC256

        val sha256 = new SHA256()
        val ecdh = new ECDHN()
        sha256.init()
        ecdh.init(256)

        SSHWriter.overBinaryProtocol(SSHMsg.KexECDHInit(ecdh.getQ))
    }
    (ecdhReply, ecdhBp) <- SSHReader.fromBinaryProtocol[SSHMsg.KexECDHReply](mac = true)
    _ <- {
        // https://github.com/the-michael-toy/jsch/blob/f9003ea83d5452d8c5e4ef8da59064195a209a05/src/main/java/com/jcraft/jsch/DHECN.java#L125-L181
        SSHWriter.overBinaryProtocol(SSHMsg.NewKeys)
    }
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