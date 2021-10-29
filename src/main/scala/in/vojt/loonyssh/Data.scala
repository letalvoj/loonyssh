package in.vojt.loonyssh

import scala.compiletime.*
import java.io.*
import scala.reflect.ClassTag

/**
 * A string containing a comma-separated list of names.  A name-list
 * is represented as a uint32 containing its length (number of bytes
 * that follow) followed by a comma-separated list of zero or more
 * names.  A name MUST have a non-zero length, and it MUST NOT
 * contain a comma (",").  As this is a list of names, all of the
 * elements contained are names and MUST be in US-ASCII.
 */
opaque type NameList[V] <: Seq[V] = Seq[V]
object NameList:
    inline def apply[V](values: Seq[V]): NameList[V] = values

opaque type FixedSizeList[L <: Int, V] = Seq[V]
object FixedSizeList:
    inline def apply[L <: Int, V](seq: Seq[V]): FixedSizeList[L, V] =
        assert(seq.length == constValue[L])
        seq

    extension[L <: Int, V] (ls: FixedSizeList[L, V]) {
        def toSeq: Seq[V] = ls
    }