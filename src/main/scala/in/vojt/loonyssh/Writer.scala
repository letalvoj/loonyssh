package in.vojt.loonyssh

import java.io._
import java.nio.ByteBuffer
import scala.reflect.ClassTag

import scala.deriving._
import scala.compiletime._
import scala.language.implicitConversions

import scala.util.control.NonFatal

trait SSHWriter[V]: // IO / Writer monad? then we could you flatmap
    def write(value:V, os: OutputStream): Unit // the os param could be implicit
    
    // cats &| other FP lib
    def coMap[W](f:W=>V):SSHWriter[W] = new SSHWriter[W]:
        def write(value:W, os: OutputStream): Unit =
            SSHWriter.this.write(f(value),os)
            
object SSHWriter:

    inline def apply[V](using impl: SSHWriter[V]):SSHWriter[V] = impl

    given intWriter as SSHWriter[Int] = (i, os) =>
        println(s"I --->>> ${i}")
        os.write(ByteBuffer.allocate(4).putInt(i).array)
    given byteWriter as SSHWriter[Byte] = (b, os) =>
        println(s"B --->>> ${b}")
        os.write(b)
    given arrayWriter as SSHWriter[Array[Byte]] = (b, os) =>
        println(s"A --->>> ${b.toSeq}")
        os.write(b)
    given seqWriter[V:SSHWriter] as SSHWriter[Seq[V]] = (s, os) => s.foreach(v => SSHWriter[V].write(v, os))

    given stringWriter as SSHWriter[String] = (s, os) => {
        SSHWriter[Int].write(s.length, os)
        SSHWriter[Array[Byte]].write(s.getBytes, os)
    }

    given identificationWriter as SSHWriter[Identification] = (i, os) => SSHWriter[String].write(i.name, os)

    def wrap[V<:SSHMsg[Byte]:SSHWriter](value:V, cypherBlockSize:Int=0): BinaryPacket[Array[Byte]] = {
            val CypherBlockSize=8 // nonsense // size excluding mac should be min 8

            val blockSize = math.max(cypherBlockSize, 8)

            // TODO write directly to the bos instead of arr
            val baos = new ByteArrayOutputStream(65536)
            SSHWriter[Byte].write(value.magic,baos)
            SSHWriter[V].write(value, baos)
            baos.flush
            
            val payload = baos.toByteArray
            
            val meat = 1 + payload.length
            val len = 4 + meat

            var padding=(-len)&(blockSize-1)
            if(padding<blockSize)
                padding += blockSize


            println(s"BP --->>> ${4} ${1} ${payload.length} ${padding}")

            BinaryPacket(
                meat+padding,
                padding.toByte,
                payload,
                Seq.fill(padding)(8),
                Seq.empty, // mac - none
            )
    }


    inline given knownLengthSeqWriter[L<:Int,T](using wr:SSHWriter[Seq[T]]) as SSHWriter[LSeq[L,T]] = (ls, os) => wr.write(ls.toSeq, os)

    inline given productWriter[V:ClassTag](using m: Mirror.ProductOf[V]) as SSHWriter[V] = (p:V, os) => {
        println(s"P --->>> $p (${p.getClass})")
        writeProduct[m.MirroredElemTypes](p.asInstanceOf)(os)(0)
    }

    inline given enumWriter[V<:Enum:ClassTag](using w: EnumSupport[V]) as SSHWriter[V] = SSHWriter[String].coMap(w.toName)
    inline given enumListWriter[V<:Enum:ClassTag](using w: EnumSupport[V]) as SSHWriter[NameList[V]] = SSHWriter[String].coMap{
        es => es.names.map(w.toName).mkString(",")
    }

    inline private def writeProduct[T](p:Product)(os: OutputStream)(i:Int):Unit = inline erasedValue[T] match
        case _: (t *: ts) =>
            summonInline[SSHWriter[t]].write(productElement[t](p,i),os)
            writeProduct[ts](p)(os)(i+1)
        case _: Unit => ()

    inline private def writeEnum[T](p:Product)(os: OutputStream)(i:Int):Unit = inline erasedValue[T] match
        case _: (t *: ts) =>
            summonInline[SSHWriter[t]].write(productElement[t](p,i),os)
            writeProduct[ts](p)(os)(i+1)
        case _: Unit => ()

    inline private def nameList[V:ClassTag](toString: V => String): SSHWriter[NameList[V]] = (nl, os) =>
        SSHWriter[String].write(nl.names.map(toString).mkString(","), os)

    given nameListWriter as SSHWriter[NameList[String]] = nameList(identity)