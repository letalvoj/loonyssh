package in.vojt.loonyssh


import java.util.logging.LogManager
import java.util.logging.{Logger => JLogger}
import java.util.logging.ConsoleHandler
import java.util.logging.Level

import org.slf4j.impl.StaticLoggerBinder

object Loggers:
  def configureLogger(): Unit =
    val stream = this.getClass.getClassLoader.getResourceAsStream("in/vojt/loonyssh/logging.properties")
    JLogger.getGlobal.addHandler(new ConsoleHandler() {
       setLevel(Level.ALL)
    })
    LogManager.getLogManager.readConfiguration(stream)
