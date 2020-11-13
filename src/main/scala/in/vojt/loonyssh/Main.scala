package in.vojt.loonyssh

import java.net._
import java.io._
import scala.io.Source
import java.nio.ByteBuffer
import scala.deriving._
import scala.compiletime._
import scala.reflect.ClassTag
import java.util.Random
// import scala.deriving.constValue

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

implicit val ctx:SSHContext = SSHContext()

val sshProtocol = for
    _ <- SSH.pure(1)
    _          <- SSH.plain(new Transport.Identification(IdentificationString))
    sIs        <- SSH[Transport.Identification]
    _           = println(sIs)
    _          <- SSH.overBinaryProtocol(Kex)
    (kxO, kxB) <- SSH.fromBinaryProtocol[SSHMsg.KexInit]
    _          = println(kxO)
    // // todo dh exchange
    _          <- SSH.overBinaryProtocol(SSHMsg.NewKeys)
    // _          <- SSH.fromBinaryProtocol[SSHMsg]
yield
    sIs

def connect(bis: BufferedInputStream, bos: BufferedOutputStream) = 
    val errOrRes = sshProtocol.read(BinaryProtocol(bis,bos))
    errOrRes match{
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

@main def LoonySSH():Unit =
    val soc = new Socket("sdf.org", 22)
    // val soc = new Socket("testing_docker_container", 12345) 
    // val soc = new Socket("localhost", 20002) 

    val bis = new BufferedInputStream(soc.getInputStream)
    val bos = new BufferedOutputStream(soc.getOutputStream)

    try
        connect(bis, bos)
    finally
        bos.flush
        soc.close