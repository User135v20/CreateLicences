import javax0.license3j.{Feature, License}
import javax0.license3j.crypto.LicenseKeyPair
import javax0.license3j.io.{IOFormat, KeyPairWriter, LicenseWriter}

import java.text.SimpleDateFormat
import org.apache.commons.cli._

object CreateLicences {

  def main(args: Array[String]) {

/*
    val options = new Options
    options.addOption("mau", true, "number of active users per month")


    val parser = new DefaultParser
    val commandLine = parser.parse(options, args)
*/




    val activeUsers = 12
    val owner = "617ab3fa5a6005446075637f"

    val license = new License
    val keyPair = LicenseKeyPair.Create.from("RSA", 512)

    license.setLicenseId

    val formatter = new SimpleDateFormat("yyyy-mm-dd hh:mm:ss.SSS")
    val date = formatter.parse("2023-01-01 01:01:01.000")
    license.setExpiry(date)

    license.sign(keyPair.getPair().getPrivate(), "SHA")
    license.add(Feature.Create.intFeature("mau", activeUsers))
    license.add(Feature.Create.stringFeature("owner", s"${owner}"))

    println(license.toString)

    var writerLicense = new LicenseWriter(s"license-${owner}")
    writerLicense.write(license, IOFormat.BINARY)

    var writerKey = new KeyPairWriter(s"private-${owner}", s"public-${owner}")
    writerKey.write(keyPair, IOFormat.BINARY)
  }
}
