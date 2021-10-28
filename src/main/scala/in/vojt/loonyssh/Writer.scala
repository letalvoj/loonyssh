package in.vojt.loonyssh

import java.io.*
import java.nio.ByteBuffer
import scala.reflect.ClassTag
import scala.deriving.*
import scala.compiletime.*
import scala.language.implicitConversions
import scala.reflect.classTag
import scala.util.control.NonFatal

trait SSHWriter[V]: // IO / Writer monad? then we could you flatmap

    def write(value:V, bp: BinaryProtocol): ErrOr[Unit]

    // cats &| other FP lib
    def coMap[W](f:W=>V):SSHWriter[W] = new SSHWriter[W]:
        def write(value:W, bp: BinaryProtocol): ErrOr[Unit] =
            SSHWriter.this.write(f(value),bp)

object SSHWriter:

    inline def apply[V](using impl: SSHWriter[V]):SSHWriter[V] = impl

    given intWriter: SSHWriter[Int] = (i, bp) => bp.putInt(i)
    given byteWriter: SSHWriter[Byte] = (b, bp) => bp.put(b)
    given arrayWriter: SSHWriter[Array[Byte]] = (b, bp) => bp.putByteArray(b)
    given seqWriter[V:SSHWriter]: SSHWriter[Seq[V]] = (s, bp) =>
        ErrOr.traverse(s.map(v => SSHWriter[V].write(v, bp)).toList).map(_ => ())

    given stringWriter: SSHWriter[String] = (s, bp) => {
        SSHWriter[Int].write(s.length, bp)
        SSHWriter[Array[Byte]].write(s.getBytes, bp)
    }

    given identification: SSHWriter[Transport.Identification] = (iden, bp) =>
        println(s"> I --->>> $iden")
        SSHWriter[Array[Byte]].write(iden.version.getBytes, bp)

    inline given knownLengthSeqWriter[L<:Int,T](using wr:SSHWriter[Seq[T]]): SSHWriter[LSeq[L,T]] = (ls, bp) => wr.write(ls.toSeq, bp)

    inline given productWriter[V:ClassTag](using mv: Mirror.ProductOf[V]): SSHWriter[V] = (p:V, bp) => {
        println(s"> P --->>> $p (${p.getClass})")
        writeProduct[mv.MirroredElemTypes](p.asInstanceOf)(bp)(0)
    }
    inline given enumWriter[V<:SSHEnum:ClassTag](using w: EnumSupport[V]): SSHWriter[V] = SSHWriter[String].coMap{ x =>
        println(s"> E --->>> $x, $w, ${summon[ClassTag[V]]}")
        w.toName(x)
    }
    inline given enumListWriter[V<:SSHEnum:ClassTag](using w: EnumSupport[V]): SSHWriter[NameList[V]] = SSHWriter[String].coMap{
        es => es.names.map(w.toName).mkString(",")
    }
    inline private def writeProduct[T](p:Product)(bp: BinaryProtocol)(i:Int):ErrOr[Unit] = inline erasedValue[T] match
        case _: (t *: ts) =>
            for
                _ <- summonInline[SSHWriter[t]].write(p.productElement(i).asInstanceOf,bp)
                _ <- writeProduct[ts](p)(bp)(i+1)
            yield ()
        case _ => Right(())

    inline private def writeEnum[T<:SSHEnum](p:Product)(bp: BinaryProtocol)(i:Int):ErrOr[Unit] = inline erasedValue[T] match
        case _: (t *: ts) =>
            for
                _ <- summonInline[SSHWriter[t]].write(p.productElement(i).asInstanceOf,bp)
                _ <- writeProduct[ts](p)(bp)(i+1)
            yield ()
        case _ => Right(())

    inline private def nameList[V:ClassTag](toString: V => String): SSHWriter[NameList[V]] = (nl, bp) =>
        SSHWriter[String].write(nl.names.map(toString).mkString(","), bp)

    given nameListWriter: SSHWriter[NameList[String]] = nameList(identity)
