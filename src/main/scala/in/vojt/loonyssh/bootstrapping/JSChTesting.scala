package in.vojt.loonyssh.bootstrapping

import com.jcraft.jsch.JSch
import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.{Logger => JSChLogger}
import java.util.logging.Logger
import java.util.logging.Level

import in.vojt.loonyssh.Loggers

class JSChTestingLogger extends JSChLogger() {
  Loggers.configureLogger()

  private val logger = Logger.getLogger("jsch")
  logger.setLevel(Level.ALL)

  override def isEnabled(level: Int): Boolean = logger.isLoggable(toJDK(level))

  override def log(level: Int, message: String): Unit = logger.log(toJDK(level), message)

  private def toJDK(level: Int): Level = level match {
    case JSChLogger.DEBUG => Level.ALL
    case JSChLogger.INFO => Level.INFO
    case JSChLogger.WARN => Level.WARNING
    case JSChLogger.ERROR => Level.SEVERE
    case _ => Level.OFF
  }
}

object JSChTesting {
  System.setProperty("java.util.logging.SimpleFormatter.format",
    "[%1$tY-%1$tm-%1$td %1$tH:%1$tM:%1$tS] (%4$-6s) [%2$s] %5$s%6$s%n")

  JSch.setLogger(new JSChTestingLogger())

  JSch.setConfig("kex", "ecdh-sha2-nistp256")
  JSch.setConfig("server_host_key", "ssh-rsa")
  JSch.setConfig("cipher.s2c", "aes128-ctr")
  JSch.setConfig("cipher.c2s", "aes128-ctr")
  JSch.setConfig("mac.s2c", "hmac-sha1")
  JSch.setConfig("mac.c2s", "hmac-sha1")
  JSch.setConfig("compression.s2c", "none,zlib")
  JSch.setConfig("compression.c2s", "none,zlib")
  JSch.setConfig("eckCiphers", "")

  def main(args: Array[String]): Unit = {
    val jsch = new JSch()

    val session = jsch.getSession("user", "localhost", 20002)
    session.setPassword("user")
    session.setConfig("StrictHostKeyChecking", "no")
    session.connect()

    val command = "lsof -i :80"

    val channel = session.openChannel("exec").asInstanceOf[ChannelExec]
    channel.setCommand(command)
    channel.setInputStream(System.in)
    channel.setOutputStream(System.out)
    channel.setErrStream(System.err)

    channel.connect()
    session.disconnect()
  }
}
