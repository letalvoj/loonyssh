package in.vojt.loonyshh

import java.io._
import java.nio.ByteBuffer
import scala.reflect.ClassTag

import scala.deriving._
import scala.compiletime._

enum Error:
    case Unexpected(e:Exception)
    
type ErrOr[V] = Either[Error, V]

trait SSHReader[V]: // IO / Reader monad?
    def read(is: BufferedInputStream): V // should return ErrOr[V]

    def map[W](f:V=>W):SSHReader[W] = new SSHReader[W]:
        def read(is: BufferedInputStream): W = f(SSHReader.this.read(is))

    def flatMap[W](f:V=>SSHReader[W]):SSHReader[W] = new SSHReader[W]:
        def read(is: BufferedInputStream): W = f(SSHReader.this.read(is)).read(is)

object SSHReader:
    inline def apply[V](using impl: SSHReader[V]):SSHReader[V] = impl

    given intReader as SSHReader[Int] = is => ByteBuffer.wrap(is.readNBytes(4)).getInt
    given byteReader as SSHReader[Byte] = is => is.read().toByte

    inline def arrayReader(n:Int) = new SSHReader[Array[Byte]]:
        def read(is: BufferedInputStream): Array[Byte] = is.readNBytes(n)

    given stringReader as SSHReader[String] = for {
        n <- SSHReader[Int]
        a <- arrayReader(n)
    } yield new String(a)

    // should but can not be in Data, because of the inline restriction
    inline given lSeq[L<:Int, T:ClassTag] as SSHReader[LSeq[L,T]] = new SSHReader:
        def read(is: BufferedInputStream): LSeq[L, T] = 
            LSeq[L,T](Array.fill(constValue[L])(summonInline[SSHReader[T]].read(is)).toSeq)

    inline given derived[V](using m: Mirror.ProductOf[V]) as SSHReader[V] = new SSHReader:
        def read(is: BufferedInputStream): V = m.fromProduct(
            readProduct[m.MirroredElemTypes](is)(0).asInstanceOf
        ).asInstanceOf[V]
        
    inline private def readProduct[T](is: BufferedInputStream)(i:Int):Tuple = inline erasedValue[T] match
        case _: (t *: ts) => summonInline[SSHReader[t]].read(is) *: readProduct[ts](is)(i+1)
        case _: Unit => ()