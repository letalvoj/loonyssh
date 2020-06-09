package in.vojt.loonyssh

import java.io.{BufferedInputStream, BufferedOutputStream,InputStream}
import java.net.Socket
import java.nio.ByteBuffer
import scala.reflect.ClassTag

import java.net._
import java.io._

import scala.deriving._
import scala.compiletime._
import scala.language.implicitConversions

import scala.util.control.NonFatal
import scala.annotation.tailrec
import scala.collection.mutable.ArrayBuffer

trait SSHReader[S]: // IO / State monad?
    def read(t: BinaryProtocol): ErrOr[S]

    // cats &| other FP lib
    def map[W](f:S=>W):SSHReader[W] = new SSHReader[W]:
        def read(t: BinaryProtocol): ErrOr[W] =
            SSHReader.this.read(t).map(f)

    def flatMap[W](f:S=>SSHReader[W]):SSHReader[W] = new SSHReader[W]:
        def read(t: BinaryProtocol): ErrOr[W] =
            SSHReader.this.read(t).map(f).flatMap(r => r.read(t))

object SSHReader:

    inline def apply[S](using impl: SSHReader[S]):SSHReader[S] = impl

    inline def pure[S](s:S):SSHReader[S] = pure(Right(s))
    inline def pure[S](eos:ErrOr[S]):SSHReader[S] = t => eos

    def fromBinaryPacket[S:SSHReader]:SSHReader[(S,Transport.BinaryPacket)] = new SSHReader:
        def read(t: BinaryProtocol) = for {
            bp <- SSHReader[Transport.BinaryPacket].read(t)
            bbp = BinaryProtocol(
                ByteBuffer.wrap(bp.payload),
                ByteBuffer.allocate(0)
            )
            s  <- SSHReader[S].read(bbp)
        } yield (s, bp)

    def write[S:SSHWriter](s:S):SSHReader[Unit] = 
        bb => SSHWriter[S].write(s, bb).map(_ => bb.flush)

    given SSHReader[Unit] = bb => Right(())

    given SSHReader[Transport.Identification] = bb => ErrOr catchNonFatal {
        new Transport.Identification(new String(readIdentification(bb)).trim)
    }

    private def readIdentification(bb:BinaryProtocol):Array[Byte] =
        val buf = new ArrayBuffer[Byte](100)
        @tailrec def loop(prev:Byte):ArrayBuffer[Byte] = Seq(prev, bb.get.toByte) match {
            case crlf@Seq('\r','\n') =>
                buf.appendAll(crlf)
            case Seq(prev, curr) =>
                buf.append(prev)
                loop(curr)
        }
        loop(bb.get).toArray[Byte]


    given SSHReader[Int]  = bb => ErrOr.catchNonFatal(bb.getInt)
    given SSHReader[Byte] = bb => ErrOr.catchNonFatal(bb.get)

    inline def arrayReader(n:Int):SSHReader[Array[Byte]] =
        bb => ErrOr.catchNonFatal(bb.getByteArray(n))

    given SSHReader[String] = for {
        n <- SSHReader[Int]
        a <- arrayReader(n)
    } yield new String(a)

    given SSHReader[Transport.BinaryPacket] = for {
        lm <- SSHReader[Int] // how to convert BB to IS reader
        lp <- SSHReader[Byte]
        magic <- SSHReader[Byte]
        payload <- arrayReader(lm - lp - 2)
        padding <- arrayReader(lp)
        _ = println(s"got padding of len ${padding.size}")
        mac <- arrayReader(0)
    } yield new Transport.BinaryPacket(lm,lp,magic,payload,padding,mac)

    given SSHReader[NameList[String]] = SSHReader[String].map(s => NameList(s.split(",").toList))

    inline given lseqReader[L<:Int, T:ClassTag:SSHReader] as SSHReader[LSeq[L,T]] = br =>
        val len = constValue[L]
        val list = List.fill(len)(SSHReader[T].read(br))
        for
            l <- ErrOr.traverse(list)
        yield
            LSeq[L,T](l)

    inline given productReader[V<:Product:ClassTag](using m: Mirror.ProductOf[V]) as SSHReader[V] = br => {
        val p = readProduct[m.MirroredElemTypes](br)(0)
        ErrOr.traverse(p).map{
            case () => m.fromProduct(Product0) // Unit != Tuple
            case t  => m.fromProduct(t.asInstanceOf)
        }.asInstanceOf[ErrOr[V]]
    }

    inline private def readProduct[T](br: BinaryProtocol)(i:Int):Tuple = inline erasedValue[T] match
        case _: (t *: ts) =>
            val reader = summonInline[SSHReader[t]]
            reader.read(br) *: readProduct[ts](br)(i+1)
        case _: Unit => ()

    inline given enumReader[V <: Enum: ClassTag](using e:EnumSupport[V]) as SSHReader[V] =
        SSHReader[String].flatMap(name => SSHReader.pure(parseOrUnknown[V](name)))

    inline given nameListEnumReader[V <: Enum: ClassTag](using e: EnumSupport[V]) as SSHReader[NameList[V]] =
        SSHReader[String].flatMap(s => {
            val errOrs = s.split(",").map(parseOrUnknown[V](_)).toList
            val errOrList = ErrOr.traverse(errOrs).map(NameList(_))
            SSHReader.pure(errOrList)
        })

    inline def parseOrUnknown[V<:Enum](name:String)(using sup:EnumSupport[V], ct:ClassTag[V]):ErrOr[V] =
        sup.fromName.get(name).orElse{
            sup.byName("Unknown", Tuple1(name))
        }.toRight{
            Err.Unk(ct.runtimeClass.toString, "Unknown")
        }

    trait ByKey[V <: Enum, K: SSHReader](f:V => K):
        def values: Array[V] // hack to expose values from Enum companion object
        lazy val byKey = values.map{ x => f(x) -> x }.toMap

        given reader as SSHReader[V] = for {
            k <- SSHReader[K]
            e  = byKey.get(k).toRight(Err.Unk(this.getClass.getSimpleName, k))
            v <- SSHReader.pure(e)
        } yield v

