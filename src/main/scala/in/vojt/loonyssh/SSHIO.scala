package in.vojt.loonyssh

import java.net._
import java.io._

trait SSHIO[S](using reader:SSHReader[S]):
    def run(is:InputStream, os:OutputStream): ErrOr[S] =
        SSHReader[S].read(new InputStreamBinaryParser(is))
        
    def map[W:SSHReader](f:S=>W):SSHIO[W] = new SSHIO[W]:
        override def run(is:InputStream, os:OutputStream): ErrOr[W] =
            SSHIO.this.run(is, os).map(f)

    def flatMap[W:SSHReader](f:S=>SSHIO[W]):SSHIO[W] = new SSHIO[W]:
        override def run(is:InputStream, os:OutputStream): ErrOr[W] =
            SSHIO.this.run(is, os).map(f).flatMap(r => r.run(is, os))

    // def withFilter(p: S => Boolean): SSHIO[S] = SSHIO.WithFilter(p)

        
object SSHIO:

    inline def apply[S:SSHReader]:SSHIO[S] = new SSHIO[S]{}

    inline def pure[A](a:A):SSHIO[A] = new SSHIO[A]()(using SSHReader.pure(a)){}
    inline def pure[S](eo:ErrOr[S]):SSHIO[S] = new SSHIO[S]()(using SSHReader.pure(eo)){}

    def write[S:SSHWriter](s:S):SSHIO[Unit] = new SSHIO[Unit]:
        override def run(is:InputStream, os:OutputStream): ErrOr[Unit] =
            SSHWriter[S].write(s,os).map(_ => os.flush)
            
    def fromBinaryPacket[S:SSHReader]:SSHIO[(S,Transport.BinaryProtocol)] = new SSHIO:
        override def run(is:InputStream, os:OutputStream) =
            SSHReader.fromBinaryPacket[S].read(new InputStreamBinaryParser(is))

    private [loonyssh] case class WithFilter[S:SSHReader](filter: S => Boolean) extends SSHIO[S]:
        override def run(is:InputStream, os:OutputStream): ErrOr[S] =
            super.run(is,os)//.filterOrElse(filter, Err.Oth(""))