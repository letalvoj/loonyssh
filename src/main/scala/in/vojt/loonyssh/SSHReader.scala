package in.vojt.loonyssh

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.net.Socket
import java.nio.ByteBuffer
import scala.reflect.ClassTag
import java.net.*
import java.io.*
import scala.deriving.*
import scala.compiletime.*
import scala.language.implicitConversions
import scala.util.control.NonFatal
import scala.annotation.tailrec
import scala.collection.mutable.ArrayBuffer

trait SSHReader[S]:
    def read(t: BinaryProtocol): ErrOr[S]

    // cats &| other FP lib
    def map[W](f: S => W): SSHReader[W] = new SSHReader[W] :
        def read(t: BinaryProtocol): ErrOr[W] =
            SSHReader.this.read(t).map(f)

    def flatMap[W](f: S => SSHReader[W]): SSHReader[W] = new SSHReader[W] :
        def read(t: BinaryProtocol): ErrOr[W] =
            SSHReader.this.read(t).map(f).flatMap(r => r.read(t))

object SSHReader:

    inline def apply[S](using impl: SSHReader[S]): SSHReader[S] = impl

    inline def pure[S](eos: ErrOr[S]): SSHReader[S] = t => eos

    def fromBinaryProtocol[S: SSHReader]: SSHReader[(S, Transport.BinaryPacket)] = bb =>
        for {
            bp <- SSHReader[Transport.BinaryPacket].read(bb)
            bbp = BinaryProtocol(
                ByteBuffer.wrap(bp.payload),
                ByteBuffer.allocate(0)
            )
            s <- SSHReader[S].read(bbp)
        } yield (s, bp)

    given SSHReader[Unit] = bb => Right(())

    given SSHReader[Transport.Identification] = bb =>
        readIdentification(bb).map(arr => new Transport.Identification(new String(arr).trim))

    private def readIdentification(bin: BinaryProtocol): ErrOr[Array[Byte]] =
        val buf = new ArrayBuffer[Byte](1024)

        @tailrec def loop(prev: Byte): ErrOr[ArrayBuffer[Byte]] = (prev, bin.get) match {
            case (_, e@Left(_)) => e.asInstanceOf
            case ('\r', Right('\n')) =>
                buf.append('\r'.toByte)
                buf.append('\n'.toByte)
                Right(buf)
            case (prev, Right(curr)) =>
                buf.append(prev)
                loop(curr)
        }

        for
            curr <- bin.get
            buf <- loop(curr)
        yield
            buf.toArray[Byte]


    given SSHReader[Int] = bb => bb.getInt

    given SSHReader[Byte] = bb => bb.get

    inline def arrayReader(n: Int): SSHReader[Array[Byte]] =
        bb => bb.getByteArray(n)

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
        mac <- arrayReader(0)
    } yield new Transport.BinaryPacket(lm, lp, magic, payload, padding, mac)

    given SSHReader[NameList[String]] = SSHReader[String].map(s => NameList(s.split(",").toList))

    inline given lseqReader[L <: Int, T: ClassTag : SSHReader]: SSHReader[LSeq[L, T]] = br =>
        val len = constValue[L]
        val list = List.fill(len)(SSHReader[T].read(br))
        for
            l <- ErrOr.traverse(list)
        yield
            LSeq[L, T](l)

    inline given productReader[V <: Product : ClassTag](using m: Mirror.ProductOf[V]): SSHReader[V] = br => {
        val p = readProduct[m.MirroredElemTypes](br)(0)
        ErrOr.traverse(p).map(m.fromProduct).asInstanceOf[ErrOr[V]]
    }

    inline private def readProduct[T](br: BinaryProtocol)(i: Int): Tuple = inline erasedValue[T] match
        case _: (t *: ts) =>
            val reader = summonInline[SSHReader[t]]
            reader.read(br) *: readProduct[ts](br)(i + 1)
        case _ => Tuple()

    inline given enumReader[V <: SSHEnum : ClassTag](using e: EnumSupport[V]): SSHReader[V] =
        SSHReader[String].flatMap(name => SSHReader.pure(parseOrUnknown[V](name)))

    inline given nameListEnumReader[V <: SSHEnum : ClassTag](using e: EnumSupport[V]): SSHReader[NameList[V]] =
        SSHReader[String].flatMap(s => {
            val errOrs = s.split(",").map(parseOrUnknown[V](_)).toList
            val errOrList = ErrOr.traverse(errOrs).map(NameList(_))
            SSHReader.pure(errOrList)
        })

    inline def parseOrUnknown[V <: SSHEnum](name: String)(using sup: EnumSupport[V], ct: ClassTag[V]): ErrOr[V] =
        sup.fromName.get(name).orElse {
            sup.byName("Unknown", Tuple1(name))
        }.toRight {
            Err.Unk(ct.runtimeClass.toString, "Unknown")
        }

    trait ByKey[V <: SSHEnum, K: SSHReader](f: V => K):
        def values: Array[V] // hack to expose values from Enum companion object

        lazy val byKey = values.map { x => f(x) -> x }.toMap

        given reader: SSHReader[V] = for {
            k <- SSHReader[K]
            e = byKey.get(k).toRight(Err.Unk(this.getClass.getSimpleName, k))
            v <- SSHReader.pure(e)
        } yield v