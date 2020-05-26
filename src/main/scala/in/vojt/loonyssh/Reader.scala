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

enum Err:
    case Exc(e:Exception)
    case Unk[K](e:String, k:K)
    
type ErrOr[V] = Either[Err, V]

object ErrOr:
    def exception[V](value: => V):ErrOr[V] = try Right(value) catch {
        case NonFatal(e:Exception) => Left(Err.Exc(e))
    }

trait SSHReader[V]: // IO / Reader monad?
    def read(is: BufferedInputStream): ErrOr[V] // should return ErrOr[V]

    // cats &| other FP lib
    def map[W](f:V=>W):SSHReader[W] = new SSHReader[W]:
        def read(is: BufferedInputStream): ErrOr[W] =
            SSHReader.this.read(is).map(f)

    def flatMap[W](f:V=>SSHReader[W]):SSHReader[W] = new SSHReader[W]:
        def read(is: BufferedInputStream): ErrOr[W] = 
            SSHReader.this.read(is).map(f).flatMap(_.read(is))

object SSHReader:

    trait ByKey[V <: Enum, K:SSHReader](f:V => K):
        def values: Array[V]
        lazy val byKey = values.map(x => f(x) -> x).toMap
        
        given reader as SSHReader[V] =
            SSHReader[K].flatMap(x => SSHReader.pure(byKey.get(x).toRight(Err.Unk("",x))))

    inline def apply[V](using impl: SSHReader[V]):SSHReader[V] = impl

    inline def pure[V](v:V) = new SSHReader[V]:
        def read(is: BufferedInputStream): ErrOr[V] = Right(v)

    inline def pure[V](e:ErrOr[V]) = new SSHReader[V]:
        def read(is: BufferedInputStream): ErrOr[V] = e

    given intReader as SSHReader[Int] = is => ErrOr.exception{
        ByteBuffer.wrap(is.readNBytes(4)).getInt
    }
    given byteReader as SSHReader[Byte] = is => ErrOr.exception{
        is.read().toByte
    }

    inline def arrayReader(n:Int) = new SSHReader[Array[Byte]]:
        def read(is: BufferedInputStream): ErrOr[Array[Byte]] = 
            ErrOr exception is.readNBytes(n)

    given stringReader as SSHReader[String] = for {
        n <- SSHReader[Int]
        a <- arrayReader(n)
    } yield new String(a)

    // should but can not be in Data, because of the inline restriction
    inline given lSeq[L<:Int, T:ClassTag:SSHReader] as SSHReader[LSeq[L,T]] = new SSHReader:
        def read(is: BufferedInputStream): ErrOr[LSeq[L, T]] = 
            val len = constValue[L]
            val list = List.fill(len)(SSHReader[T].read(is))
            for
                l <- traverse(list)
            yield
                LSeq[L,T](l)

    inline given derived[V](using m: Mirror.ProductOf[V]) as SSHReader[V] = new SSHReader:
        def read(is: BufferedInputStream): ErrOr[V] =
            val p = readProduct[m.MirroredElemTypes](is)(0)
            traverse(p).map(t => m.fromProduct(t.asInstanceOf).asInstanceOf[V])

    private def traverse(t:Tuple):ErrOr[Tuple] = t match {
        case (e:ErrOr[Any]) *: ts => 
            for
                r <- e
                rs <- traverse(ts)
            yield r *: rs
        case _ => // _:Unit
            Right(())
    }

    private def traverse[T](t:List[ErrOr[T]]):ErrOr[List[T]] = t match {
        case e :: ts => 
            for
                r <- e
                rs <- traverse(ts)
            yield r :: rs
        case Nil => Right(Nil)
    }
    
    inline private def readProduct[T](is: BufferedInputStream)(i:Int):Tuple = inline erasedValue[T] match
        case _: (t *: ts) => summonInline[SSHReader[t]].read(is) *: readProduct[ts](is)(i+1)
        case _: Unit => ()

    inline given enumReader[V <: Enum](using e:EnumSupport[V]) as SSHReader[V] = {
        SSHReader[String].flatMap(x => pure(e.fromName.get(x).toRight(Err.Unk("",x))))
    }

    given plain as SSHReader[NameList[String]] = 
        SSHReader[String].map(s => NameList(s.split(",").toList))

    inline given enumerated[V <: Enum : ClassTag](using e: EnumSupport[V]) as SSHReader[NameList[V]] =
        for
            s <- SSHReader[String]
            x <- pure(traverse(s.split(",").toList.map(x => e.fromName.get(x).toRight(Err.Unk("",x)))))
        yield
            NameList(x)

    inline given known[V <: Enum : ClassTag](using e: EnumSupport[V]) as SSHReader[NameList[Known[V]]] =
        SSHReader[String].map(s => NameList(s.split(",").map(name => {
            e.fromName.get(name).toRight(name)
        }).toList))