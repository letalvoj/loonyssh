package in.vojt.rework

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
            
