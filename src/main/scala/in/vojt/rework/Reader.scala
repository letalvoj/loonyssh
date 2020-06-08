package in.vojt.rework

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

import in.vojt.loonyssh.{LSeq, NameList, IdentificationString, Product0, SSHMsg, EnumSupport}

trait BinaryReader:
    def getInt:Int =
        val res = _getInt
        println(s"getInt ->          $res")
        res

    def get:Byte =
        val res = _get
        println(s"get ->             $res")
        res
    
    def getByteArray(n:Int):Array[Byte] =
        val res = _getByteArray(n)
        println(s"getByteArray ->    ${res.map(toChar).mkString.take(130)}...")
        res
    

    private def toChar(i:Byte) = if(i > 32 && i < 127) i.toChar.toString else f"\u${i}%02X"

    protected def _getInt:Int
    protected def _get:Byte
    protected def _getByteArray(n:Int):Array[Byte]

case class InputStreamBinaryReader(is: InputStream) extends BinaryReader:
    def _getInt = ByteBuffer.wrap(is.readNBytes(4)).getInt
    def _get = is.read.toByte
    def _getByteArray(n:Int) = is.readNBytes(n)


case class ByteBufferBinaryReader(bb: ByteBuffer) extends BinaryReader:
    def _getInt = bb.getInt
    def _get = bb.get
    def _getByteArray(n:Int) = if(n > 0) Array.fill(n)(bb.get) else Array.empty

/*

MSG
 - Version
 - Binary Packer Format
    - Transport Layer ...


case class BPF(len,pad,magic,payload,padding,size)

SSHReader[TCPMsg, SSHMsg]
(message:Version, version:String) <- SSHReader[Version, String]
(binaryPacket:BPF, msg:KexInit) <- SSHReader[BPF, KexInit]

*/

enum Transport:
    case Identification(version:String)
    case BinaryProtocol(
        len:Int,
        pad:Byte,
        magic:Byte,
        payload:Array[Byte],
        padding:Array[Byte],
        mac:Array[Byte])

trait SSHReader[T,S]: // IO / State monad?
    def read(t: T): ErrOr[(T,S)]

    //  // somehow merge it with flatMap?
    // def flip[N](t: T)(f:S=>ErrOr[(S,N)]):SSHReader[S,N] = new SSHReader[S,N]:
    //     def read(implicit s: S): ErrOr[(S,N)] =
    //         SSHReader.this.read(t).flatMap((t,s) => f(s))

    // cats &| other FP lib
    def map[W](f:S=>W):SSHReader[T,W] = new SSHReader[T,W]:
        def read(implicit t: T): ErrOr[(T,W)] =
            SSHReader.this.read(t).map((tt,w) => (tt,f(w)))

    def flatMap[W](f:S=>SSHReader[T,W]):SSHReader[T,W] = new SSHReader[T,W]:
        def read(implicit t: T): ErrOr[(T,W)] =
            SSHReader.this.
                read(t).
                map((tt,s) => (tt,f(s))).
                flatMap((tt, r) => r.read(tt))

object SSHReader:

    type BB[M] = SSHReader[BinaryReader, M]

    inline def apply[T,S](using impl: SSHReader[T,S]):SSHReader[T,S] = impl

    inline def pure[T,S](t:T, s:S):SSHReader[T,S] = pure(Right((t,s)))
    inline def pure[T,S](eos:ErrOr[(T,S)]):SSHReader[T,S] = implicit t => eos

    given SSHReader[BinaryReader, Transport.Identification] = implicit bb => ErrOr exception {
        new Transport.Identification(new String(readIdentification(bb)).trim)
    }

    private def readIdentification(bb:BinaryReader):Array[Byte] =
        val buf = new ArrayBuffer[Byte](100)
        @tailrec def loop(prev:Int):ArrayBuffer[Byte] = (prev, bb.get) match {
            case ('\r','\n') => 
                buf.append('\r'.toByte)
                buf.append('\n'.toByte)
            case (prev, curr) => 
                buf.append(prev.toByte)
                loop(curr)
        }
        loop(bb.get).toArray[Byte]
    

    given SSHReader.BB[Int] = implicit bb => ErrOr exception bb.getInt
    given SSHReader.BB[Byte] = implicit bb => ErrOr exception bb.get

    inline def arrayReader(n:Int):SSHReader.BB[Array[Byte]] = 
        implicit bb => ErrOr exception bb.getByteArray(n)

    given SSHReader.BB[String] =
        for
            n <- SSHReader[BinaryReader, Int]
            a <- arrayReader(n)
        yield new String(a)

    given SSHReader.BB[Transport.BinaryProtocol] =
        for
            lm <- SSHReader[BinaryReader, Int] // how to convert BB to IS reader
            lp <- SSHReader[BinaryReader, Byte]
            magic <- SSHReader[BinaryReader, Byte]
            payload <- arrayReader(lm-lp-1)
            padding <- arrayReader(lp)
            mac <- arrayReader(0)
        yield
            new Transport.BinaryProtocol(lm,lp,magic,payload,padding,mac)

    given SSHReader.BB[NameList[String]] = SSHReader[BinaryReader, String].map(s => NameList(s.split(",").toList))

    inline given lseqReader[L<:Int, T:ClassTag:SSHReader.BB] as SSHReader.BB[LSeq[L,T]] = implicit br =>
        val len = constValue[L]
        val list = List.fill(len)(SSHReader[BinaryReader,T].read(br))
        for
            l <- ErrOr.traverse(list)
        yield
            (br, LSeq[L,T](l.map(_._2)))

    inline given productReader[V<:Product:ClassTag](using m: Mirror.ProductOf[V]) as SSHReader.BB[V] = implicit br => {
        val p = readProduct[m.MirroredElemTypes](br)(0)
        println(s"PROD: ${p}")
        ErrOr.traverse(p).map{
            case () => (br, m.fromProduct(Product0).asInstanceOf[V]) // Unit != Tuple
            case t  => (br, m.fromProduct(t.asInstanceOf).asInstanceOf[V])
        }
    }

    inline private def readProduct[T](br: BinaryReader)(i:Int):Tuple = inline erasedValue[T] match
        case _: (t *: ts) =>
            val reader = summonInline[SSHReader[BinaryReader,t]]
            println(s"productValue ${reader}")
            reader.read(br).asInstanceOf[ErrOr[(_, t)]].map(_._2) *: readProduct[ts](br)(i+1)
        case _: Unit => ()

    inline given enumReader[V <: Enum](using e:EnumSupport[V]) as SSHReader.BB[V] =
        SSHReader[BinaryReader,String].map(parseOrUnknown[V](_))

    inline given nameListEnumReader[V <: Enum: ClassTag](using e: EnumSupport[V]) as SSHReader.BB[NameList[V]] =
        SSHReader[BinaryReader, String].map(s => NameList(s.split(",").map(parseOrUnknown[V](_)).toList))

    inline def parseOrUnknown[V<:Enum](name:String)(using sup:EnumSupport[V]) =
        sup.fromName.get(name).getOrElse(sup.byName("Unknown", Tuple1(name)).get)


def connect(bis: BufferedInputStream, bos: BufferedOutputStream) = 
    bos.write(IdentificationString.getBytes)
    bos.flush

    val isbr = InputStreamBinaryReader(bis)

    val ident = SSHReader[BinaryReader, Transport.Identification].read(isbr)
    println(ident)

    val bpKex = SSHReader[BinaryReader, Transport.BinaryProtocol].read(isbr)
    println(s"bpKex: $bpKex")

    val bbbr = ByteBufferBinaryReader(ByteBuffer.wrap(bpKex.toOption.get._2.payload))
    val kex = SSHReader.productReader[SSHMsg.KexInit].read(bbbr)
    println(s"kex: $kex")

    // SSHWriter[BinaryPacket[Array[Byte]]].write(SSHWriter.wrap(Kex), bos)
    // bos.flush

    // SSHWriter[BinaryPacket[Array[Byte]]].write(SSHWriter.wrap(SSHMsg.NewKeys), bos)
    // bos.flush

    // println("Remaining:")
    // LazyList.continually(bis.read).
    //     map(c => (c + 256) % 256).
    //     map(c => f"-${c}%02X").
    //     take(30).
    //     foreach(print)

@main def Rework():Unit = 
    println("compile")

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

    // val baos = new ByteArrayOutputStream(65536)
    // SSHWriter[BinaryPacket[Array[Byte]]].write(SSHWriter.wrap(Kex), baos)
    // baos.flush
    // println(s"baos ${baos.toByteArray.toSeq}")

    // // Currently fails since the binary packet is not serialized properly
    // val pos = new PipedOutputStream()
    // val pis = new PipedInputStream(pos)
    // val bpis = new BufferedInputStream(pis)

    // SSHWriter[BinaryPacket[Array[Byte]]].write(SSHWriter.wrap(Kex), pos)
    // val kexRecoveder = SSHReader[BinaryPacket[SSHMsg.KexInit]].read(pis)
    // println(Right(Kex) == kexRecoveder.map(_.payload)) // false
    // pos.close
