package in.vojt.loonyssh

import com.jcraft.jsch.jce.HMACSHA1
import com.jcraft.jsch.jce.SHA256
import com.jcraft.jsch.jce.AES128CTR

case class SSHContext(sessionId: Option[Array[Byte]] = None,
                      sha256: Option[SHA256] = None,
                      cypherC2S: Option[AES128CTR] = None,
                      cypherS2C: Option[AES128CTR] = None,
                      macC2S: Option[HMACSHA1] = None,
                      macS2C: Option[HMACSHA1] = None) {

    // todo remove mutable state
    var seqo:Int = 0
    var seqi:Int = 0

    def cypherC2SBlockSize: Int =
        cypherC2S.map(_.getBlockSize).getOrElse(0) max 8

    def cypherS2CBlockSize: Int =
        cypherS2C.map(_.getBlockSize).getOrElse(0) max 8
}

object SSHContex:
    given SSHContext = SSHContext()