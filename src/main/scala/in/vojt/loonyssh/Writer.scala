package in.vojt.loonyshh

import in.vojt.loonyshh.names._
import in.vojt.loonyshh.enums._

import java.io._
import java.nio.ByteBuffer
import scala.reflect.ClassTag

import scala.deriving._
import scala.compiletime._
import scala.language.implicitConversions

import scala.util.control.NonFatal

trait SSHWriter[V]: // IO / Writer monad? then we could you flatmap
    def write(value:V, os: OutputStream): Unit // the os param could be implicit

object SSHWriter:

    inline def apply[V](using impl: SSHWriter[V]):SSHWriter[V] = impl

    given intWriter as SSHWriter[Int] = (i, os) => os.write(ByteBuffer.allocate(4).putInt(i).array)
    given byteWriter as SSHWriter[Byte] = (b, os) => os.write(b)
    given arrayWriter as SSHWriter[Array[Byte]] = (b, os) => os.write(b)
    given seqWriter[V:SSHWriter] as SSHWriter[Seq[V]] = (s, os) => s.foreach(v => SSHWriter[V].write(v, os))

    given stringWriter as SSHWriter[String] = (s, os) => {
        SSHWriter[Int].write(s.length, os)
        SSHWriter[Array[Byte]].write(s.getBytes, os)
    }

    given identificationWriter as SSHWriter[Identification] = (i, os) => SSHWriter[String].write(i.name, os)

    def wrap[V<:Product:SSHWriter](value:V): BinaryPacket[Array[Byte]] = {
            val CypherBlockSize=8 // nonsense // size excluding mac should be min 8

            val baos = new ByteArrayOutputStream(65536)
            SSHWriter[V].write(value, baos)
            baos.flush
            val payload = baos.toByteArray
            val meat = 4 + 1 + payload.length
            val overflow = meat % CypherBlockSize
            val padding = CypherBlockSize - overflow

            BinaryPacket(
                meat+padding,
                padding.toByte,
                payload,
                Seq.fill(padding)(0),
                Seq.empty, // mac <- // not yet implemented
            )
    }


    inline given knownLengthSeqWriter[L<:Int,T](using wr:SSHWriter[Seq[T]]) as SSHWriter[LSeq[L,T]] = (ls, os) => wr.write(ls.toSeq, os)

    inline given productWriter[V](using m: Mirror.ProductOf[V], ct:ClassTag[V]) as SSHWriter[V] = (ls:V, os) => {
        // match statement can not be used as of 0.24-RC1
        if (ls.isInstanceOf[SSHMsg[_]])
            os.write(ls.asInstanceOf[SSHMsg[_]].magic)
        writeProduct[m.MirroredElemTypes](ls.asInstanceOf)(os)(0)
    }

    inline private def writeProduct[T](p:Product)(os: OutputStream)(i:Int):Unit = inline erasedValue[T] match
        case _: (t *: ts) =>
            summonInline[SSHWriter[t]].write(productElement[t](p,i),os)
            writeProduct[ts](p)(os)(i+1)
        case _: Unit => ()

    inline private def nameList[V:ClassTag](toString: V => String): SSHWriter[NameList[V]] = (nl, os) =>
        SSHWriter[String].write(nl.names.map(toString).mkString(","), os)

    given nameListWriter as SSHWriter[NameList[String]] = nameList(identity)
