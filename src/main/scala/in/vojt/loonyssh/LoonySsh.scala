package in.vojt.loonyshh

import java.net._
import java.io._
import scala.io.Source
import java.nio.ByteBuffer
import scala.deriving._
import scala.compiletime._
import scala.reflect.ClassTag


val IdentificationString = "SSH-2.0-loonySSH_0.0.1\r\n"
val kex = SSHMsg.KexInit(
            cookie = LSeq(List(60, -106, 65, -27, -9, -90, -111, -70, 32, 83, -121, 108, 31, -92, -103, -36)),
            kexAlgorithms = NameList(List("curve25519-sha256")),
            serverHostKeyAlgorithms = NameList(List("ssh-ed25519")),
            encryptionAlgorithmsClientToServer = NameList(List("chacha20-poly1305@openssh.com")),
            encryptionAlgorithmsServerToClient = NameList(List("chacha20-poly1305@openssh.com")),
            macAlgorithmsClientToServer = NameList(List("hmac-sha2-256")),
            macAlgorithmsServerToClient = NameList(List("hmac-sha2-256")),
            compressionAlgorithmsClientToServer = NameList(List("none")),
            compressionAlgorithmsServerToClient = NameList(List("none")),
            languagesClientToServer = NameList(List()),
            languagesServerToClient = NameList(List()),
            kexFirstPacketFollows = 0,
            reserved = 0
        )

@main def loonymain():Unit =
    val socket = new Socket("sdf.org", 22)

    val inStr = new BufferedInputStream(socket.getInputStream)
    val outStr = socket.getOutputStream

    outStr.write(IdentificationString.getBytes)
    outStr.flush

    val ident = SSHReader[Identification].read(inStr)
    println(ident)

    val kex = summon[SSHReader[BinaryPacket[SSHMsg.KexInit]]].read(inStr)
    println(s"kex: $kex")
    println(s"ea : ${kex.map(_.payload.encryptionAlgorithmsClientToServer)}")

    // LazyList.continually(inStr.read).map{
    //     case c if c < 0 => (c + 256, c.toChar)
    //     case c          => (c, c.toChar)
    //     // case c if c < 128  => c.toChar
    //     // case _ => '�'
    // }.take(100).foreach(println)

    outStr.flush
    socket.close
