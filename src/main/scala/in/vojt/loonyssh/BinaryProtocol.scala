package in.vojt.loonyssh

import java.io.{BufferedInputStream, BufferedOutputStream,InputStream,OutputStream}
import java.net.Socket
import java.nio.ByteBuffer
import scala.reflect.ClassTag

import scala.deriving._
import scala.compiletime._
import scala.language.implicitConversions

import scala.util.control.NonFatal
import scala.annotation.tailrec
import scala.collection.mutable.ArrayBuffer

//TODO error handling should be pushed here
// so far all these ops are unsafe
trait BinaryProtocol:

    protected def _getInt:Int
    protected def _get:Byte
    protected def _getByteArray(n:Int):Array[Byte]

    protected def _putInt(v:Int):Unit
    protected def _put(v:Byte):Unit
    protected def _putByteArray(v:Array[Byte]):Unit

    def flush:Unit
    def sn:String

    def getInt:Int = log(s"> I <<<-$sn ", _getInt, identity)
    def get:Byte   = log(s"> B <<<-$sn ", _get, identity)
    def getByteArray(n:Int):Array[Byte] = log(
        s"> A <<<-$sn ", _getByteArray(n), 
        arr => s"[${arr.map(toChar).mkString.take(130)}...]"
    )

    def putInt(v:Int):Unit =
        _putInt(v)
        println(s"> I $sn->>> $v")

    def put(v:Byte):Unit =
        _put(v)
        println(s"> B $sn->>> $v")

    def putByteArray(v:Array[Byte]):Unit =
        _putByteArray(v)
        println(s"> A $sn->>> [${v.map(toChar).mkString.take(130)}...]")

    private def log[V,O](prefix:String, v:V, format:V=>O):V = 
        println(s"$prefix ${format(v)}")
        return v

    private def toChar(i:Byte) = if(i > 32 && i < 127) i.toChar.toString else f"\u${i}%02X"

object BinaryProtocol:
    def apply(is: InputStream, os: OutputStream) = 
        InputStreamBinaryProtocol(is, os)
    def apply(bbi: ByteBuffer, bbo: ByteBuffer) = 
        ByteBufferBinaryProtocol(bbi, bbo)
    
case class InputStreamBinaryProtocol(is: InputStream, os: OutputStream) extends BinaryProtocol:
    def _getInt = ByteBuffer.wrap(is.readNBytes(4)).getInt
    def _get = is.read.toByte
    def _getByteArray(n:Int) = 
        println(s"> Avail <? ${is.available()} Req $n")
        is.readNBytes(n)

    def _putInt(v:Int):Unit = os.write(ByteBuffer.allocate(4).putInt(v).array)
    def _put(v:Byte):Unit = os.write(Array[Byte](v))
    def _putByteArray(v:Array[Byte]):Unit = os.write(v)

    def flush:Unit = os.flush
    val sn = "is"

case class ByteBufferBinaryProtocol(bbi: ByteBuffer, bbo: ByteBuffer) extends BinaryProtocol:
    def _getInt = bbi.getInt
    def _get = bbi.get
    def _getByteArray(n:Int) = if(n > 0) Array.fill(n)(bbi.get) else Array.empty

    def _putInt(v:Int):Unit               = bbo.putInt(v)
    def _put(v:Byte):Unit                 = bbo.put(v)
    def _putByteArray(v:Array[Byte]):Unit = bbo.put(v)

    def flush:Unit = ()
    val sn = "bb"

    // inline private def unsuported: Unit =
    //     throw UnsupportedOperationException(
    //         s"Never ${getClass.getSimpleName} to write.Should be used in fromBinaryPacket only."
    //     )