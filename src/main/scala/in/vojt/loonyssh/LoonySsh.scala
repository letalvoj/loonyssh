package in.vojt.loonyshh

import java.net._
import java.io._
import scala.io.Source
import java.nio.ByteBuffer
import scala.compiletime.{constValue, summonInline, erasedValue, S}
import scala.reflect.ClassTag

import scala.deriving._

val IdentificationString = "SSH-2.0-loonySSH_0.0.1\r\n"

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
