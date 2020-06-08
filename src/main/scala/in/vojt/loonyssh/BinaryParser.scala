package in.vojt.loonyssh

import java.io.{BufferedInputStream, BufferedOutputStream,InputStream}
import java.net.Socket
import java.nio.ByteBuffer
import scala.reflect.ClassTag

import scala.deriving._
import scala.compiletime._
import scala.language.implicitConversions

import scala.util.control.NonFatal
import scala.annotation.tailrec
import scala.collection.mutable.ArrayBuffer

trait BinaryParser:
    def getInt:Int =
        val res = _getInt
        println(s"getInt ->          $res")
        res

    def get:Byte =
        val res = _get
        println(s"get ->             $res")
        res

    def getByteArray(n:Int):Array[Byte] =
        println(s"getByteArray($n)")
        val res = _getByteArray(n)
        println(s"getByteArray ->    ${res.map(toChar).mkString.take(130)}...")
        res


    private def toChar(i:Byte) = if(i > 32 && i < 127) i.toChar.toString else f"\u${i}%02X"

    protected def _getInt:Int
    protected def _get:Byte
    protected def _getByteArray(n:Int):Array[Byte]

case class InputStreamBinaryParser(is: InputStream) extends BinaryParser:
    def _getInt = ByteBuffer.wrap(is.readNBytes(4)).getInt
    def _get = is.read.toByte
    def _getByteArray(n:Int) = 
        println(s"available <- ${is.available()}")
        is.readNBytes(n)


case class ByteBufferBinaryParser(bb: ByteBuffer) extends BinaryParser:
    def _getInt = bb.getInt
    def _get = bb.get
    def _getByteArray(n:Int) = if(n > 0) Array.fill(n)(bb.get) else Array.empty


object ByteBufferBinaryParser:
    def apply(array:Array[Byte]) = new ByteBufferBinaryParser(ByteBuffer.wrap(array))