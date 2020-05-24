package in.vojt.loonyshh

import java.io._
import java.nio.ByteBuffer
import scala.reflect.ClassTag

import scala.deriving._
import scala.compiletime._

trait SSHReader[V]: // reader monad?
    def read(is: BufferedInputStream): V // should be Either

    def map[W](f:V=>W):SSHReader[W] = new SSHReader[W]:
        def read(is: BufferedInputStream): W = f(SSHReader.this.read(is))

    def flatMap[W](f:V=>SSHReader[W]):SSHReader[W] = new SSHReader[W]:
        def read(is: BufferedInputStream): W = f(SSHReader.this.read(is)).read(is)


opaque type LSeq[L<:Int, V] = Seq[V]
object LSeq:
    def apply[L<:Int, V](seq:Seq[V]):LSeq[L,V] = seq

object SSHReader:
    inline def apply[V](using impl: SSHReader[V]):SSHReader[V] = impl

    inline given lSeq[L<:Int, T:ClassTag] as SSHReader[LSeq[L,T]] = new SSHReader:
        def read(is: BufferedInputStream): LSeq[L, T] = 
            LSeq[L,T](Array.fill(constValue[L])(summonInline[SSHReader[T]].read(is)).toSeq)

    given intReader as SSHReader[Int] = is => ByteBuffer.wrap(is.readNBytes(4)).getInt
    given byteReader as SSHReader[Byte] = is => is.read().toByte

    inline def arrayReader(n:Int) = new SSHReader[Array[Byte]]:
        def read(is: BufferedInputStream): Array[Byte] = is.readNBytes(n)

    given stringReader as SSHReader[String] = for {
        n <- SSHReader[Int]
        a <- arrayReader(n)
    } yield new String(a)

    inline given derived[V](using m: Mirror.ProductOf[V]) as SSHReader[V] = new SSHReader:
        def read(is: BufferedInputStream): V = 
            val parsed = readProduct[m.MirroredElemTypes](is)(0)
            m.fromProduct(parsed.asInstanceOf[Product]).asInstanceOf[V]
        
    inline private def readProduct[T](is: BufferedInputStream)(i:Int):Tuple = inline erasedValue[T] match
        case _: (t *: ts) => summonInline[SSHReader[t]].read(is) *: readProduct[ts](is)(i+1)
        case _: Unit => ()