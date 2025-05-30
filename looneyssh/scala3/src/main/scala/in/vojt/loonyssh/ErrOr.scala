package in.vojt.loonyssh

import java.io.*
import java.nio.ByteBuffer
import scala.reflect.ClassTag
import scala.deriving.*
import scala.compiletime.*
import scala.language.implicitConversions
import scala.util.control.NonFatal

enum Err:
    case Exc(e: Exception)
    case Unk[K](expl: String, k: K)
    case Oth(expl: String)
    case Magic(exp: Int, act: Int)
    case FailedPattern
    case EmptyWriter

type ErrOr[V] = Either[Err, V]

object ErrOr:
    def catchNonFatal[V](value: => V): ErrOr[V] = try Right(value) catch
        case NonFatal(e: Exception) => Left(Err.Exc(e))

    def catchIO[V](value: => V): ErrOr[V] = try Right(value) catch
        case e: IOException => Left(Err.Exc(e))

    def traverse(t: Tuple): ErrOr[Tuple] = t match
        case e *: ts =>
            for
                r <- e.asInstanceOf[ErrOr[?]]
                rs <- traverse(ts)
            yield r *: rs
        case t: Tuple => Right(t)


    def traverse[T](t: List[ErrOr[T]]): ErrOr[List[T]] = t match
        case Nil => Right(Nil)
        case e :: ts =>
            for
                r <- e
                rs <- traverse(ts)
            yield r :: rs