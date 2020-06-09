package in.vojt.loonyssh

import java.net._
import java.io._
import scala.io.Source
import java.nio.ByteBuffer
import scala.deriving._
import scala.compiletime._
import scala.reflect.ClassTag
import java.util.Random

val ClientName = "LoonySSH"
val ClientVersion = "0.0.1"
val IdentificationString = s"SSH-2.0-${ClientName}_${ClientVersion}\r\n"

val Kex = 
    SSHMsg.KexInit(
        cookie = LSeq[4,Int](List.fill(4)(4)),
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
        reserved = 0)

val sshProtocol = for
    _          <- SSHIO.write(new Transport.Identification(IdentificationString))
    sIs        <- SSHIO[Transport.Identification]
    _           = println(sIs)
    _          <- SSHIO.write(SSHWriter.wrap(Kex))
    (kxO, kxB) <- SSHIO.fromBinaryPacket[SSHMsg.KexInit]
    // kxT <- SSHIO.fromBinaryPacket[SSHMsg.KexInit]
    // (kxO, kxB) = kxT
    _          = println((kxO, kxB))
    _          <- SSHIO.write(SSHWriter.wrap(SSHMsg.NewKeys))
yield
    kxO

def connect(bis: BufferedInputStream, bos: BufferedOutputStream) = 
    val res = sshProtocol.run(bis, bos)
    println("RESULT:" + res)        
    //  import com.jcraft.jsch.jce.AES128CTR
    //  import com.jcraft.jsch.{DHEC256, Utils, WrapperIO, WrapperSession}
    //  val dh = new DHEC256(ident.getBytes, IdentificationString.getBytes, ???, ???)
    //  dh.init(sess)

    println("Remaining:")
    LazyList.continually(bis.read).
        map(c => f"${c}%02X-").
        take(30).
        foreach(print)

@main def loonymain():Unit =
    // val soc = new Socket("sdf.org", 22)
    val soc = new Socket("testing_docker_container", 12345) 
    // val soc = new Socket("localhost", 20002) 

    val bis = new BufferedInputStream(soc.getInputStream)
    val bos = new BufferedOutputStream(soc.getOutputStream)

    try
        connect(bis, bos)
    finally
        bos.flush
        soc.close

    // Should be turned into a test
    // val baos = new ByteArrayOutputStream(65536)
    // SSHWriter[Transport.BinaryProtocol].write(SSHWriter.wrap(Kex), baos)
    // baos.flush
    // println(s"baos ${baos.toByteArray.toSeq}")

    // // Currently fails since the binary packet is not serialized properly
    // val pos = new PipedOutputStream()
    // val pis = new PipedInputStream(pos)
    // val bpis = new BufferedInputStream(pis)

    // SSHWriter[Transport.BinaryProtocol].write(SSHWriter.wrap(Kex), pos)
    // val kexRecoveder = SSHReader[BinaryPacket[SSHMsg.KexInit]].read(pis)
    // println(Right(Kex) == kexRecoveder.map(_.payload)) // false
    // pos.close