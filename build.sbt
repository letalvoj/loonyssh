// val dottyVersion = "0.24.0-RC1"
val dottyVersion = dottyLatestNightlyBuild.get
val loonVersion = "0.1.0"
val deps = List(
      "com.novocode" % "junit-interface" % "0.11" % "test",
      "com.jcraft" % "jsch" % "0.1.55",
      // "dev.zio" %% "izumi-reflect" % "1.0.0-M2", // not available for 0.24
      // ("org.typelevel" %% "cats-core" % "2.1.1").withDottyCompat(scalaVersion.value),
    )

scalacOptions ++= List(
  "-verbose",
  "-Ydebug"
)
scalacOptions in (Compile, console) += "-Xprint:typer"

lazy val messages = project
  .in(file("./messages"))
  .settings(
    name := "loonyssh-data",
    version := loonVersion,
    scalaVersion := dottyVersion,
    libraryDependencies ++= deps)
  
lazy val core = project
  .in(file("."))
  .settings(
    name := "loonyssh-core",
    version := loonVersion,
    scalaVersion := dottyVersion,
    libraryDependencies ++= deps)
  .aggregate(messages)
  .dependsOn(messages)
