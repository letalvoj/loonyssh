package in.vojt.loonyshh

import scala.compiletime._
import java.io._
import scala.reflect.ClassTag
import scala.collection.immutable.ArraySeq

/**
    A string containing a comma-separated list of names.  A name-lis
    is represented as a uint32 containing its length (number of bytes
    that follow) followed by a comma-separated list of zero or more
    names.  A name MUST have a non-zero length, and it MUST NOT
    contain a comma (",").  As this is a list of names, all of the
    elements contained are names and MUST be in US-ASCII.
*/
case class NameList[V](names:V*)

object NameList:
    inline def fromArr[B](values:Array[B]):NameList[B] = fromSeq(ArraySeq.unsafeWrapArray(values))
    inline def fromSeq[B](values:Seq[B]):NameList[B] = NameList(values:_*)

opaque type LSeq[L<:Int, V] = Seq[V]
object LSeq:
    def apply[L<:Int, V](seq:Seq[V]):LSeq[L,V] = seq

    extension on[L<:Int, V] (ls:LSeq[L, V]) {
        def toSeq:Seq[V] = ls
    }