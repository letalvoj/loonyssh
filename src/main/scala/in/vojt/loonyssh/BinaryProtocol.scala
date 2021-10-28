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

    protected def unsafeGetInt:Int
    protected def unsafeGet:Byte
    protected def unsafeGetByteArray(n:Int):Array[Byte]

    protected def unsafePutInt(v:Int):Unit
    protected def unsafePut(v:Byte):Unit
    protected def unsafePutByteArray(v:Array[Byte]):Unit

    def flush:Unit
    def sn:String

    def getInt:ErrOr[Int] =
        log("I", unsafeGetInt, identity)
    def get:ErrOr[Byte]   =
        log("B", unsafeGet, identity)
    def getByteArray(n:Int):ErrOr[Array[Byte]] =
        log("A", unsafeGetByteArray(n), orArr => orArr.map(arr => s"[${arr.map(toChar).mkString.take(130)}...]"))

    def putInt(v:Int):ErrOr[Unit] =
        println(s"> I $sn->>> $v")
        ErrOr.catchIO(unsafePutInt(v))

    def put(v:Byte):ErrOr[Unit] =
        println(s"> B $sn->>> $v")
        ErrOr.catchIO(unsafePut(v))

    def putByteArray(v:Array[Byte]):ErrOr[Unit] =
        println(s"> A $sn->>> [${v.map(toChar).mkString.take(130)}...]")
        ErrOr.catchIO(unsafePutByteArray(v))

    private def log[V,O](tp:String, eventualV: => V, format:ErrOr[V]=>O):ErrOr[V] = 
        val v = ErrOr.catchIO(eventualV)
        println(s"< $tp $sn-<<< ${format(v)}")
        return v

    private def toChar(i:Byte) = if(i > 32 && i < 127) i.toChar.toString else f"\u${i}%02X"

object BinaryProtocol:
    def apply(is: InputStream, os: OutputStream) = 
        InputStreamBinaryProtocol(is, os)
    def apply(bbi: ByteBuffer, bbo: ByteBuffer) = 
        ByteBufferBinaryProtocol(bbi, bbo)
    
case class InputStreamBinaryProtocol(is: InputStream, os: OutputStream) extends BinaryProtocol:
    def unsafeGetInt = 
        val bb = ByteBuffer.allocate(4)
        is.read(bb.array)
        bb.getInt
    def unsafeGet = is.read.toByte
    def unsafeGetByteArray(n:Int) = 
        println(s"> Avail <? ${is.available()} Req $n")
        val arr = new Array[Byte](n)
        is.read(arr)
        arr

    def unsafePutInt(v:Int) = os.write(ByteBuffer.allocate(4).putInt(v).array)
    def unsafePut(v:Byte) = os.write(Array[Byte](v))
    def unsafePutByteArray(v:Array[Byte]) = os.write(v)

    def flush:Unit = os.flush
    val sn = "is"

case class ByteBufferBinaryProtocol(bbi: ByteBuffer, bbo: ByteBuffer) extends BinaryProtocol:
    val sn = "bb"

    def unsafeGetInt = bbi.getInt
    def unsafeGet = bbi.get
    def unsafeGetByteArray(n:Int) = if(n > 0) Array.fill(n)(bbi.get) else Array.empty

    def unsafePutInt(v:Int)               = bbo.putInt(v)
    def unsafePut(v:Byte)                 = bbo.put(v)
    def unsafePutByteArray(v:Array[Byte]) = bbo.put(v)

    def flush:Unit = ()

    // inline private def unsuported: Unit =
    //     throw UnsupportedOperationException(
    //         s"Never ${getClass.getSimpleName} to write.Should be used in fromBinaryProtocol only."
    //     )