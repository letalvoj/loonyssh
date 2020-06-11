package in.vojt.loonyssh

case class SSHContext(cypherBlockSize:Byte=0)

object SSHContex:
    given SSHContext = SSHContext()