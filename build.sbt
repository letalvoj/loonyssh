val ProjectName    = "loonyssh"
val ProjectVersion = "0.0.1"
val ScalaVersion   = "0.26.0-bin-20200610-4b39622-NIGHTLY"
// val ScalaVersion   = dottyLatestNightlyBuild.get

scalacOptions += "-verbose"
scalacOptions ++= List("-source","3.1")
// scalacOptions in (Compile, console) += "-Xprint:typer"

lazy val `loonyssh` = project
  .in(file("."))
  .settings(
    name                := ProjectName,
    version             := ProjectVersion,
    scalaVersion        := ScalaVersion,
    libraryDependencies ++= List(
      "com.novocode"    % "junit-interface" % "0.11"   % "test",
      "com.jcraft"      % "jsch"            % "0.1.55",
      "net.i2p.crypto"  % "eddsa"           % "0.3.0" ,
      "org.apache.sshd" % "sshd-core"       % "2.4.0" ,
    ) ++ List(
      "org.slf4j"       % "slf4j-jdk14",
      "org.slf4j"       % "slf4j-api",
    ).map(_ % "1.7.30")
  )
