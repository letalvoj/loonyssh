package in.vojt.loonyssh.bootstrapping

import java.nio.file.{Path, Paths, Files}

import in.vojt.loonyssh.Loggers
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider

import scala.jdk.CollectionConverters._


object Server {
  Loggers.configureLogger()

  def main(args: Array[String]): Unit = {
    val sshd = SshServer.setUpDefaultServer()
    sshd.setPasswordAuthenticator((username, password, session) => true)
    sshd.setKeyPairProvider(session => List.empty.asJava)
    sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Paths.get("server.key")))
    sshd.setPort(20002)
    sshd.setHost("localhost")

    try {
      sshd.start()
      while (sshd.isStarted) {
        Thread.sleep(15000)
        println("Still running")
      }
    } finally {
      sshd.stop()
      println("DEAD")
    }
  }

}
