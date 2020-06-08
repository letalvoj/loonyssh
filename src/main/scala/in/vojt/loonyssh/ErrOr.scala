package in.vojt.loonyssh

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
    def catchNonFatal[V](value: => V):ErrOr[V] = try Right(value) catch
        case NonFatal(e:Exception) => Left(Err.Exc(e))

    def catchIO[V](value: => V):ErrOr[V] = try Right(value) catch
        case e:IOException => Left(Err.Exc(e))

    def traverse(t:Tuple):ErrOr[Tuple] = t match
        case e *: ts =>
            for
                r <- e.asInstanceOf[ErrOr[_]]
                rs <- traverse(ts)
            yield r *: rs
        case _:Tuple => Right(())


    def traverse[T](t:List[ErrOr[T]]):ErrOr[List[T]] = t match
        case Nil => Right(Nil)
        case e :: ts =>
            for
                r <- e
                rs <- traverse(ts)
            yield r :: rs