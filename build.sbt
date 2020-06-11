val dottyVersion = "0.26.0-bin-20200610-4b39622-NIGHTLY"
// val dottyVersion = dottyLatestNightlyBuild.get

// scalacOptions ++= List("-verbose") // ,"-Ydebug"

scalacOptions ++= List("-source","3.1")
scalacOptions in (Compile, console) += "-Xprint:typer"

lazy val root = project
  .in(file("."))
  .settings(
    name := "dotty-simple",
    version := "0.1.0",
    scalaVersion := dottyVersion,
    libraryDependencies ++= List(
      "com.novocode"    % "junit-interface" % "0.11"    % "test",
      "com.jcraft"      % "jsch"            % "0.1.55",
      "net.i2p.crypto"  % "eddsa"           % "0.3.0",
      "org.apache.sshd" % "sshd-core"       % "2.4.0",
      "org.slf4j"       % "slf4j-jdk14"     % "1.7.30",
      "org.slf4j"       % "slf4j-api"       % "1.7.30",
    )
  )
