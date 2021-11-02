package in.vojt.loonyssh

import com.jcraft.jsch.{Buffer => JSChBuffer}

import java.io.*
import java.nio.ByteBuffer
import scala.reflect.ClassTag
import scala.deriving.*
import scala.compiletime.*
import scala.language.implicitConversions
import scala.reflect.classTag
import scala.util.control.NonFatal

trait SSHWriter[V]: // IO / Writer monad? then we could you flatmap

    def write(bp: BinaryProtocol, value: V): ErrOr[Unit]

    // cats &| other FP lib
    def coMap[W](f: W => V): SSHWriter[W] = (bp: BinaryProtocol, w: W) =>
        SSHWriter.this.write(bp, f(w))

object SSHWriter:

    inline def apply[V](using impl: SSHWriter[V]): SSHWriter[V] = impl

    def overBinaryProtocol[V <: SSHMsg[?] : SSHWriter](v: V)(using ctx: SSHContext): SSHReader[Transport.BinaryPacket] = iop =>
        val bbp = BinaryProtocol(ByteBuffer.allocate(0), ByteBuffer.allocate(65536))
        for
            _ <- SSHWriter[V].write(bbp, v)
            data = bbp.bbo.array.take(bbp.bbo.position)
            bp = Transport(v.magic.toByte, data)
            _ <- SSHWriter[Transport.BinaryPacket].write(iop, bp)
            _ <- ErrOr.catchIO(iop.flush)
        yield bp

    def plain[V: SSHWriter](v: V): SSHReader[V] = iop =>
        for
            _ <- SSHWriter[V].write(iop, v)
            _ <- ErrOr.catchIO(iop.flush)
        yield v

    given intWriter: SSHWriter[Int] = _.putInt(_)

    given byteWriter: SSHWriter[Byte] = _.put(_)

    given arrayWriter: SSHWriter[Array[Byte]] = _.putByteArray(_)

    given mpIntWriter: SSHWriter[MPInt] = (bp, foo) =>
        if ((foo(0) & 0x80) != 0) { // msb set for positive number
            for
                _ <- intWriter.write(bp, foo.length + 1)
                _ <- byteWriter.write(bp, 0)
                _ <- arrayWriter.write(bp, foo)
            yield
                ()
        } else {
            for
                _ <- intWriter.write(bp, foo.length)
                _ <- arrayWriter.write(bp, foo)
            yield
                ()
        }

    given seqWriter: SSHWriter[Seq[Byte]] = (bp, b) =>
        bp.putInt(b.length)
        bp.putByteArray(b.toArray)

    given seqWriter[V: SSHWriter]: SSHWriter[Seq[V]] = (bp, s) =>
        ErrOr.traverse(s.map(v => SSHWriter[V].write(bp, v)).toList).map(_ => ())

    given stringWriter: SSHWriter[String] = (bp, s) => {
        SSHWriter[Int].write(bp, s.length)
        SSHWriter[Array[Byte]].write(bp, s.getBytes)
    }

    given identification: SSHWriter[Transport.Identification] = (bp, iden) =>
        println(s"> I --->>> $iden")
        SSHWriter[Array[Byte]].write(bp, iden.version.getBytes)

    inline given knownLengthSeqWriter[L <: Int, T](using wr: SSHWriter[Seq[T]]): SSHWriter[FixedSizeList[L, T]] = (bp, ls) => wr.write(bp, ls.toSeq)

    inline given productWriter[V: ClassTag](using mv: Mirror.ProductOf[V]): SSHWriter[V] = (bp, p: V) => {
        println(s"> P --->>> $p (${p.getClass})")
        writeProduct[mv.MirroredElemTypes](p.asInstanceOf)(bp)(0)
    }

    inline given enumWriter[V <: SSHEnum : ClassTag](using w: EnumSupport[V]): SSHWriter[V] = SSHWriter[String].coMap { x =>
        println(s"> E --->>> $x, $w, ${summon[ClassTag[V]]}")
        w.toName(x)
    }

    inline given enumListWriter[V <: SSHEnum : ClassTag](using w: EnumSupport[V]): SSHWriter[NameList[V]] = SSHWriter[String].coMap {
        es => es.map(w.toName).mkString(",")
    }

    inline private def writeProduct[T](p: Product)(bp: BinaryProtocol)(i: Int): ErrOr[Unit] = inline erasedValue[T] match
        case _: (t *: ts) =>
            for
                _ <- summonInline[SSHWriter[t]].write(bp, p.productElement(i).asInstanceOf)
                _ <- writeProduct[ts](p)(bp)(i + 1)
            yield ()
        case _ => Right(())

    inline private def writeEnum[T <: SSHEnum](p: Product)(bp: BinaryProtocol)(i: Int): ErrOr[Unit] = inline erasedValue[T] match
        case _: (t *: ts) =>
            for
                _ <- summonInline[SSHWriter[t]].write(bp, p.productElement(i).asInstanceOf)
                _ <- writeProduct[ts](p)(bp)(i + 1)
            yield ()
        case _ => Right(())

    inline private def nameList[V: ClassTag](toString: V => String): SSHWriter[NameList[V]] = (bp, nl) =>
        SSHWriter[String].write(bp, nl.map(toString).mkString(","))

    given nameListWriter: SSHWriter[NameList[String]] = nameList(identity)
