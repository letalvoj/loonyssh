val dottyVersion = "0.24.0-RC1"

// scalacOptions += "-language:Scala2Compat"

lazy val root = project
  .in(file("."))
  .settings(
    name := "dotty-simple",
    version := "0.1.0",

    scalaVersion := dottyVersion,
    libraryDependencies ++= List(
      "com.novocode" % "junit-interface" % "0.11" % "test",
      "com.jcraft" % "jsch" % "0.1.55",
      ("org.typelevel" %% "cats-core" % "2.1.1").withDottyCompat(scalaVersion.value),
    )
  )
