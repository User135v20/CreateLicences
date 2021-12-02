name := "CreateLicences"

version := "0.1"

scalaVersion := "2.13.7"

lazy val license3jVersion = "3.1.5"
libraryDependencies += "com.javax0.license3j" % "license3j" % license3jVersion
libraryDependencies += "commons-cli" % "commons-cli" % "1.5.0"
libraryDependencies += "ch.qos.logback" % "logback-classic" % "1.2.3"
libraryDependencies += "com.typesafe.scala-logging" %% "scala-logging" % "3.9.4"
