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

trait SSH[S]:
    def read(t: BinaryProtocol): ErrOr[S]

    // cats &| other FP lib
    def map[W](f:S=>W):SSH[W] = new SSH[W]:
        def read(t: BinaryProtocol): ErrOr[W] =
            SSH.this.read(t).map(f)

    def flatMap[W](f:S=>SSH[W]):SSH[W] = new SSH[W]:
        def read(t: BinaryProtocol): ErrOr[W] =
            SSH.this.read(t).map(f).flatMap(r => r.read(t))

object SSH:

    inline def apply[S](using impl: SSH[S]):SSH[S] = impl

    inline def pure[S](eos:ErrOr[S]):SSH[S] = t => eos

    def fromBinaryProtocol[S:SSH]:SSH[(S,Transport.BinaryPacket)] = bb =>
        for {
            bp <- SSH[Transport.BinaryPacket].read(bb)
            bbp = BinaryProtocol(
                ByteBuffer.wrap(bp.payload),
                ByteBuffer.allocate(0)
            )
            s  <- SSH[S].read(bbp)
        } yield (s, bp)

    def overBinaryProtocol[V<:SSHMsg:SSHWriter](v:V)(using ctx:SSHContext):SSH[Unit] = iop =>
        val bbp = BinaryProtocol(ByteBuffer.allocate(0),ByteBuffer.allocate(65536))
        for
            _ <- SSHWriter[V].write(v,bbp)
            data = bbp.bbo.array.take(bbp.bbo.position)
            _ <- SSHWriter[Transport.BinaryPacket].write(Transport(v.magic,data), iop)
            _ <- ErrOr.catchIO(iop.flush)
        yield ()

    def plain[V:SSHWriter](v:V):SSH[Unit] = iop =>
        for
            _ <- SSHWriter[V].write(v,iop)
            _ <- ErrOr.catchIO(iop.flush)
        yield ()

    given SSH[Unit] = bb => Right(())

    given SSH[Transport.Identification] = bb =>
        readIdentification(bb).map(arr => new Transport.Identification(new String(arr).trim))

    private def readIdentification(bin:BinaryProtocol):ErrOr[Array[Byte]] =
        val buf = new ArrayBuffer[Byte](1024)
        @tailrec def loop(prev:Byte):ErrOr[ArrayBuffer[Byte]] = (prev, bin.get) match {
            case (_, e @ Left(_)) => e.asInstanceOf
            case ('\r',Right('\n')) =>
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


    given SSH[Int]  = bb => bb.getInt
    given SSH[Byte] = bb => bb.get

    inline def arrayReader(n:Int):SSH[Array[Byte]] =
        bb => bb.getByteArray(n)

    given SSH[String] = for {
        n <- SSH[Int]
        a <- arrayReader(n)
    } yield new String(a)

    given SSH[Transport.BinaryPacket] = for {
        lm <- SSH[Int] // how to convert BB to IS reader
        lp <- SSH[Byte]
        magic <- SSH[Byte]
        payload <- arrayReader(lm - lp - 2)
        padding <- arrayReader(lp)
        mac <- arrayReader(0)
    } yield new Transport.BinaryPacket(lm,lp,magic,payload,padding,mac)

    given SSH[NameList[String]] = SSH[String].map(s => NameList(s.split(",").toList))

    inline given lseqReader[L<:Int, T:ClassTag:SSH]: SSH[LSeq[L,T]] = br =>
        val len = constValue[L]
        val list = List.fill(len)(SSH[T].read(br))
        for
            l <- ErrOr.traverse(list)
        yield
            LSeq[L,T](l)

    inline given productReader[V<:Product:ClassTag](using m: Mirror.ProductOf[V]): SSH[V] = br => {
        val p = readProduct[m.MirroredElemTypes](br)(0)
        ErrOr.traverse(p).map(m.fromProduct).asInstanceOf[ErrOr[V]]
    }

    inline private def readProduct[T](br: BinaryProtocol)(i:Int):Tuple = inline erasedValue[T] match
        case _: (t *: ts) =>
            val reader = summonInline[SSH[t]]
            reader.read(br) *: readProduct[ts](br)(i+1)
        case _ => Tuple()

    inline given enumReader[V <: SSHEnum: ClassTag](using e:EnumSupport[V]): SSH[V] =
        SSH[String].flatMap(name => SSH.pure(parseOrUnknown[V](name)))

    inline given nameListEnumReader[V <: SSHEnum: ClassTag](using e: EnumSupport[V]): SSH[NameList[V]] =
        SSH[String].flatMap(s => {
            val errOrs = s.split(",").map(parseOrUnknown[V](_)).toList
            val errOrList = ErrOr.traverse(errOrs).map(NameList(_))
            SSH.pure(errOrList)
        })

    inline def parseOrUnknown[V<:SSHEnum](name:String)(using sup:EnumSupport[V], ct:ClassTag[V]):ErrOr[V] =
        sup.fromName.get(name).orElse{
            sup.byName("Unknown", Tuple1(name))
        }.toRight{
            Err.Unk(ct.runtimeClass.toString, "Unknown")
        }

    // inline given sSHMsgReader: SSH[SSHMsg] = bbp =>
    //     // val mirror = summonInline[Mirror.Of[SSHMsg]]
    //     ???

    trait ByKey[V <: SSHEnum, K: SSH](f:V => K):
        def values: Array[V] // hack to expose values from Enum companion object
        lazy val byKey = values.map{ x => f(x) -> x }.toMap

        given reader: SSH[V] = for {
            k <- SSH[K]
            e  = byKey.get(k).toRight(Err.Unk(this.getClass.getSimpleName, k))
            v <- SSH.pure(e)
        } yield v

