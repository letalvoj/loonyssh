package in.vojt.loonyssh

import java.io._
import java.nio.ByteBuffer
import scala.reflect.ClassTag

import scala.deriving._
import scala.compiletime._
import scala.language.implicitConversions

import scala.util.control.NonFatal

trait SSHWriter[V]: // IO / Writer monad? then we could you flatmap
    
    def write(value:V, bp: BinaryProtocol): ErrOr[Unit]
    
    // cats &| other FP lib
    def coMap[W](f:W=>V):SSHWriter[W] = new SSHWriter[W]:
        def write(value:W, bp: BinaryProtocol): ErrOr[Unit] =
            SSHWriter.this.write(f(value),bp)
            
object SSHWriter:

    inline def apply[V](using impl: SSHWriter[V]):SSHWriter[V] = impl

    given intWriter as SSHWriter[Int] = (i, bp) => bp.putInt(i)
    given byteWriter as SSHWriter[Byte] = (b, bp) => bp.put(b)
    given arrayWriter as SSHWriter[Array[Byte]] = (b, bp) => bp.putByteArray(b)
    given seqWriter[V:SSHWriter] as SSHWriter[Seq[V]] = (s, bp) => 
        ErrOr.traverse(s.map(v => SSHWriter[V].write(v, bp)).toList).map(_ => ())

    given stringWriter as SSHWriter[String] = (s, bp) => {
        SSHWriter[Int].write(s.length, bp)
        SSHWriter[Array[Byte]].write(s.getBytes, bp)
    }

    given identification as SSHWriter[Transport.Identification] = (iden, bp) => 
        println(s"> I --->>> $identification")
        SSHWriter[Array[Byte]].write(iden.version.getBytes, bp)

    inline given knownLengthSeqWriter[L<:Int,T](using wr:SSHWriter[Seq[T]]) as SSHWriter[LSeq[L,T]] = (ls, bp) => wr.write(ls.toSeq, bp)

    inline given productWriter[V:ClassTag](using xxxx: Mirror.ProductOf[V]) as SSHWriter[V] = (p:V, bp) => {
        println(s"> P --->>> $p (${p.getClass})")
        writeProduct[xxxx.MirroredElemTypes](p.asInstanceOf)(bp)(0)
    }
    inline given enumWriter[V<:Enum:ClassTag](using w: EnumSupport[V]) as SSHWriter[V] = SSHWriter[String].coMap{x => 
        println(s"> E --->>> $x, $w, ${summon[ClassTag[V]]}")
        w.toName(x)
    }
    inline given enumListWriter[V<:Enum:ClassTag](using w: EnumSupport[V]) as SSHWriter[NameList[V]] = SSHWriter[String].coMap{
        es => es.names.map(w.toName).mkString(",")
    }
    inline private def writeProduct[T](p:Product)(bp: BinaryProtocol)(i:Int):ErrOr[Unit] = inline erasedValue[T] match
        case _: (t *: ts) =>
            for
                _ <- summonInline[SSHWriter[t]].write(productElement[t](p,i),bp)
                _ <- writeProduct[ts](p)(bp)(i+1)
            yield ()
        case _ => Right(())

    inline private def writeEnum[T](p:Product)(bp: BinaryProtocol)(i:Int):ErrOr[Unit] = inline erasedValue[T] match
        case _: (t *: ts) =>
            for
                _ <- summonInline[SSHWriter[t]].write(productElement[t](p,i),bp)
                _ <- writeProduct[ts](p)(bp)(i+1)
            yield ()
        case _ => Right(())

    inline private def nameList[V:ClassTag](toString: V => String): SSHWriter[NameList[V]] = (nl, bp) =>
        SSHWriter[String].write(nl.names.map(toString).mkString(","), bp)

    given nameListWriter as SSHWriter[NameList[String]] = nameList(identity)
