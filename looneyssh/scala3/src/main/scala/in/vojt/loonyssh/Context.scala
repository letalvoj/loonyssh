package in.vojt.loonyssh

import com.jcraft.jsch.jce.HMACSHA256
import com.jcraft.jsch.jce.SHA256
import com.jcraft.jsch.jce.AES128CTR

import java.util.concurrent.atomic.AtomicInteger

case class SSHContext(sessionId: Option[Array[Byte]] = None,
                      sha256: Option[SHA256] = None,
                      cypherC2S: Option[AES128CTR] = None,
                      cypherS2C: Option[AES128CTR] = None,
                      macC2S: Option[HMACSHA256] = None,
                      macS2C: Option[HMACSHA256] = None) {

    def cypherC2SBlockSize: Int =
        cypherC2S.map(_.getBlockSize).getOrElse(0) max 8

    def cypherS2CBlockSize: Int =
        cypherS2C.map(_.getBlockSize).getOrElse(0) max 8
}

object SSHContext:

    // TODO remove mutable state
    var seqo:AtomicInteger = new AtomicInteger()
    var seqi:AtomicInteger = new AtomicInteger()

    given SSHContext = SSHContext()