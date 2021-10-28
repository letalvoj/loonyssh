val Org = "in.vojt"
val ProjectName    = "loonyssh"
val ProjectVersion = "0.0.1-SNAPSHOT"
val ScalaVersion   = "3.1.0"
val MajorVersion   = ScalaVersion.split('.').take(2).mkString(".")

autoCompilerPlugins := true

lazy val `loonyssh` = project
  .in(file("."))
  .settings(
    organization        := Org,
    name                := ProjectName,
    version             := ProjectVersion,
    scalaVersion        := ScalaVersion,
    scalacOptions       ++= List("-source","3.1"),
    libraryDependencies ++= List(
      "com.novocode"    % "junit-interface" % "0.11"   % "test",
      "com.jcraft"      % "jsch"            % "0.1.55",
      "net.i2p.crypto"  % "eddsa"           % "0.3.0",
      "org.apache.sshd" % "sshd-core"       % "2.4.0",
      "org.typelevel"   %% "cats-core"      % "2.6.1",
    ) ++ List(
      "org.slf4j"       % "slf4j-jdk14",
      "org.slf4j"       % "slf4j-api",
    ).map(_ % "1.7.30"),
  )
  
//.dependsOn(`sand-box`)
// lazy val `sand-box` = project
//   .in(file("sand-box"))
//   .settings(
//     organization        := Org,
//     name                := SandboxName,
//     version             := ProjectVersion,
//     scalaVersion        := ScalaVersion,
//     scalacOptions       ++= List(
//       s"-Xplugin:${System.getProperty("user.home")}/.ivy2/local/"+
//       s"${Org}/"+
//       s"${PluginName}_${MajorVersion}/"+
//       s"${ProjectVersion}/"+
//       s"jars/${PluginName}_${MajorVersion}.jar"), // any way programatically get a ivy path from ("" %% "" % "")
//   ).dependsOn(`enhanced-mirror`)
// 
// lazy val `enhanced-mirror` = project
//   .in(file("enhanced-mirror"))
//   .settings(
//     organization        := Org,
//     name                := PluginName,
//     version             := ProjectVersion,
//     scalaVersion        := ScalaVersion,
//     //libraryDependencies ++= List(
//     //  "ch.epfl.lamp" %% "dotty-staging"  % ScalaVersion % "compile",
//     //)
//   )