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

trait SSHReader[S]: // IO / State monad?
    def read(t: BinaryParser): ErrOr[S]

    //  // somehow merge it with flatMap?
    // def flip[N](t: T)(f:S=>ErrOr[(S,N)]):SSHReader[N] = new SSHReader[N]:
    //     def read(s: S): ErrOr[(S,N)] =
    //         SSHReader.this.read(t).flatMap((t,s) => f(s))

    // cats &| other FP lib
    def map[W](f:S=>W):SSHReader[W] = new SSHReader[W]:
        def read(t: BinaryParser): ErrOr[W] =
            SSHReader.this.read(t).map(f)

    def flatMap[W](f:S=>SSHReader[W]):SSHReader[W] = new SSHReader[W]:
        def read(t: BinaryParser): ErrOr[W] =
            SSHReader.this.read(t).map(f).flatMap(r => r.read(t))

object SSHReader:

    type BB[M] = SSHReader[M]

    inline def apply[S](using impl: SSHReader[S]):SSHReader[S] = impl

    inline def pure[S](s:S):SSHReader[S] = pure(Right(s))
    inline def pure[S](eos:ErrOr[S]):SSHReader[S] = t => eos

    trait ByKey[V <: Enum, K:SSHReader](f:V => K):
        def values: Array[V]

        lazy val byKey = values.map{ x => f(x) -> x }.toMap
        given reader as SSHReader[V] =
            SSHReader[K].flatMap(x => SSHReader.pure(byKey.get(x).toRight(
                new Err.Unk(this.getClass.getSimpleName, x)
            )))

    given SSHReader[Transport.Identification] = bb => ErrOr exception {
        new Transport.Identification(new String(readIdentification(bb)).trim)
    }

    private def readIdentification(bb:BinaryParser):Array[Byte] =
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


    given SSHReader[Int]  = bb => ErrOr exception bb.getInt
    given SSHReader[Byte] = bb => ErrOr exception bb.get

    inline def arrayReader(n:Int):SSHReader[Array[Byte]] =
        bb => ErrOr exception bb.getByteArray(n)

    given SSHReader[String] =
        for
            n <- SSHReader[Int]
            a <- arrayReader(n)
        yield new String(a)

    given SSHReader[Transport.BinaryProtocol] =
        for
            lm <- SSHReader[Int] // how to convert BB to IS reader
            lp <- SSHReader[Byte]
            magic <- SSHReader[Byte]
            payload <- arrayReader(lm - lp - 2)
            padding <- arrayReader(lp)
            _ = println(s"got padding of len ${padding.size}")
            mac <- arrayReader(0)
        yield
            new Transport.BinaryProtocol(lm,lp,magic,payload,padding,mac)

    given SSHReader[NameList[String]] = SSHReader[String].map(s => NameList(s.split(",").toList))

    inline given lseqReader[L<:Int, T:ClassTag:SSHReader.BB] as SSHReader[LSeq[L,T]] = br =>
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

    inline private def readProduct[T](br: BinaryParser)(i:Int):Tuple = inline erasedValue[T] match
        case _: (t *: ts) =>
            val reader = summonInline[SSHReader[t]]
            reader.read(br) *: readProduct[ts](br)(i+1)
        case _: Unit => ()

    inline given enumReader[V <: Enum](using e:EnumSupport[V]) as SSHReader[V] =
        SSHReader[String].map(parseOrUnknown[V](_))

    inline given nameListEnumReader[V <: Enum: ClassTag](using e: EnumSupport[V]) as SSHReader[NameList[V]] =
        SSHReader[String].map(s => NameList(s.split(",").map(parseOrUnknown[V](_)).toList))

    inline def parseOrUnknown[V<:Enum](name:String)(using sup:EnumSupport[V]) =
        sup.fromName.get(name).getOrElse(sup.byName("Unknown", Tuple1(name)).get)