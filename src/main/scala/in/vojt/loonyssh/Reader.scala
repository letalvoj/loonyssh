package in.vojt.loonyshh

import java.io._
import java.nio.ByteBuffer
import scala.reflect.ClassTag

import scala.deriving._
import scala.compiletime._

trait SshReader[V]: // reader monad?
    def read(is: BufferedInputStream): V // should be Either

    def map[W](f:V=>W):SshReader[W] = new SshReader[W]:
        def read(is: BufferedInputStream): W = f(SshReader.this.read(is))

    def flatMap[W](f:V=>SshReader[W]):SshReader[W] = new SshReader[W]:
        def read(is: BufferedInputStream): W = f(SshReader.this.read(is)).read(is)


opaque type LSeq[L<:Int, V] = Seq[V]
object LSeq:
    def apply[L<:Int, V](seq:Seq[V]):LSeq[L,V] = seq

object SshReader:
    inline def apply[V](using impl: SshReader[V]):SshReader[V] = impl

    inline given lSeq[L<:Int, T:ClassTag] as SshReader[LSeq[L,T]] = new SshReader:
        def read(is: BufferedInputStream): LSeq[L, T] = 
            LSeq[L,T](Array.fill(constValue[L])(summonInline[SshReader[T]].read(is)).toSeq)

    given intReader as SshReader[Int] = is => ByteBuffer.wrap(is.readNBytes(4)).getInt
    given byteReader as SshReader[Byte] = is => is.read().toByte

    inline def arrayReader(n:Int) = new SshReader[Array[Byte]]:
        def read(is: BufferedInputStream): Array[Byte] = is.readNBytes(n)

    given stringReader as SshReader[String] = for {
        n <- SshReader[Int]
        a <- arrayReader(n)
    } yield new String(a)

    inline given derived[V](using m: Mirror.ProductOf[V]) as SshReader[V] = new SshReader:
        def read(is: BufferedInputStream): V = 
            val parsed = readProduct[m.MirroredElemTypes](is)(0)
            m.fromProduct(parsed.asInstanceOf[Product]).asInstanceOf[V]
        
    inline private def readProduct[T](is: BufferedInputStream)(i:Int):Tuple = inline erasedValue[T] match
        case _: (t *: ts) => summonInline[SshReader[t]].read(is) *: readProduct[ts](is)(i+1)
        case _: Unit => ()