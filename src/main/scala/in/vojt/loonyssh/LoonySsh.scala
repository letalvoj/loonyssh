package in.vojt.loonyshh

import java.net._
import java.io._
import scala.io.Source
import java.nio.ByteBuffer
import scala.deriving._
import scala.compiletime._
import scala.reflect.ClassTag
import java.util.Random
import in.vojt.loonyshh.names._

val ClientName = "LoonySSH"
val ClientVersion = "0.0.1"
val IdentificationString = s"SSH-2.0-${ClientName}_${ClientVersion}\r\n"

val Kex = 
    SSHMsg.KexInit(
        cookie = LSeq[4,Int](List.iterate((new Random(), 0), 4)((r, i) => (r, r.nextInt)).map(_._2)),
        kexAlgorithms = NameList(KeyExchangeMethod.`ecdh-sha2-nistp256`),
        serverHostKeyAlgorithms = NameList(PublicKeyAlgorithm.`ssh-rsa`),
        encryptionAlgorithmsClientToServer = NameList(EncryptionAlgorithm.`aes128-ctr`),
        encryptionAlgorithmsServerToClient = NameList(EncryptionAlgorithm.`aes128-ctr`),
        macAlgorithmsClientToServer = NameList(MACAlgorithm.`hmac-sha2-256`),
        macAlgorithmsServerToClient = NameList(MACAlgorithm.`hmac-sha2-256`),
        compressionAlgorithmsClientToServer = NameList(CompressionAlgorithm.`none`),
        compressionAlgorithmsServerToClient = NameList(CompressionAlgorithm.`none`),
        languagesClientToServer = NameList(),
        languagesServerToClient = NameList(),
        kexFirstPacketFollows = 0,
        reserved = 0)

@main def loonymain():Unit =
    // connecting to a random public server
    val soc = new Socket("sdf.org", 22)

    val bis = new BufferedInputStream(soc.getInputStream)
    val bos = new BufferedOutputStream(soc.getOutputStream)

    bos.write(IdentificationString.getBytes)
    bos.flush

    val ident = SSHReader[Identification].read(bis)
    println(ident)

    val kex = SSHReader[BinaryPacket[SSHMsg.KexInit]].read(bis)
    println(s"kex: $kex")

    // // Currently fails since the binary packet is not serialized properly
    // val pos = new PipedOutputStream()
    // val pis = new PipedInputStream(pos)
    // val bpis = new BufferedInputStream(pis)
    // SSHWriter[BinaryPacket[Array[Byte]]].write(SSHWriter.wrap(Kex), pos)
    // val kexRecoveder = SSHReader[SSHMsg.KexInit].read(pis)
    // println(kexRecoveder)
    // pos.close

    // println("Remaining:")
    // LazyList.continually(bis.read).
    //     map(c => (c + 256) % 256).
    //     map(c => f"${c}%02X").
    //     take(30).
    //     foreach(print)

    bos.flush
    soc.close
