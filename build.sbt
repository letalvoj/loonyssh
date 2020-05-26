val dottyVersion = "0.24.0-RC1"

scalacOptions in (Compile, console) += "-Xprint:typer"

lazy val root = project
  .in(file("."))
  .settings(
    name := "dotty-simple",
    version := "0.1.0",

    scalaVersion := dottyVersion,
    libraryDependencies ++= List(
      "com.novocode" % "junit-interface" % "0.11" % "test",
      "com.jcraft" % "jsch" % "0.1.55",
      // "dev.zio" %% "izumi-reflect" % "1.0.0-M2", // not available for 0.24
      ("org.typelevel" %% "cats-core" % "2.1.1").withDottyCompat(scalaVersion.value),
    )
  )
