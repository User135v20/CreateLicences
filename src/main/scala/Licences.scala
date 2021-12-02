import com.typesafe.scalalogging.{Logger}
import javax0.license3j.{Feature, License}
import javax0.license3j.crypto.LicenseKeyPair
import javax0.license3j.io.{IOFormat, KeyPairWriter, LicenseWriter}

import java.text.SimpleDateFormat
import org.apache.commons.cli._

import java.util.{Date}


object Licences {
  val logger = Logger("CreateLicences")

  private val MAU = "m"
  private val OWN = "o"
  private val DATE = "d"
  private val DATEFORMAT ="yyyy-mm-dd hh:mm:ss"
  private val KEYCIPHER = "RSA"
  private val KEYSIZE = 512
  private val LICENSEDIGEST = "SHA"
  private val LICENSEOWN = "owner"
  private val LICENSEMAU = "mau"


  val options = new Options
  options.addOption(MAU, true, "number of active users per month")
  options.addOption(OWN, true, "id of the company for which the license is issued")
  options.addOption(DATE, true, s"expiry date. format: ${DATEFORMAT}")


  def parsingMAU( cmd: CommandLine): Int = {
    try {
      val activeUsers = cmd.getOptionValue(MAU).toInt
      logger.debug(s"parse from cmd. ${options.getOption(MAU).getDescription}: ${activeUsers}")
      activeUsers
    } catch {
      case ex: NumberFormatException =>
        logger.debug(s"Error parsing number of active users per month")
        -1
    }
  }

  def parsingOWN(cmd: CommandLine): String = {
    val owner = cmd.getOptionValue(OWN)
    logger.debug(s"parse from cmd. ${options.getOption(OWN).getDescription}: ${owner}")
    owner
  }

  def parsingDATE(cmd: CommandLine): Date = {
    logger.debug(s"parse from cmd.${options.getOption(DATE).getDescription}")
    val formatter = new SimpleDateFormat(DATEFORMAT)
    val rowDate = cmd.getOptionValue(DATE)
    formatter.parse(rowDate)
  }

  def createKeyPair(keyCipher: String, keySize: Int, nameCompany: String): LicenseKeyPair ={
    logger.debug("create key pair")
    val keyPair = LicenseKeyPair.Create.from(keyCipher, keySize)
    writeKey(keyPair,nameCompany)
    keyPair
  }

  def createLicence(cmd: CommandLine ): License ={
    logger.debug("start of license creation")
    val license = new License

    license.setLicenseId
    logger.debug("set license id")

    license.setExpiry(parsingDATE(cmd))
    logger.debug("set license date")

    license.add(Feature.Create.intFeature(LICENSEMAU, parsingMAU(cmd)))
    logger.debug(s"add license ${options.getOption(MAU).getDescription}")
    val idCompany = parsingOWN(cmd)
    license.add(Feature.Create.stringFeature(LICENSEOWN, idCompany))
    logger.debug(s"add license ${options.getOption(OWN).getDescription} ")
    license.sign(createKeyPair(KEYCIPHER,KEYSIZE, idCompany).getPair().getPrivate(), LICENSEDIGEST)
    logger.debug("sign license")
    license
  }

  def writeLicence(license: License): Unit = {
    logger.debug("record license to file")
    val writerLicense = new LicenseWriter(s"license-${license.getFeatures.get(LICENSEOWN).getString}")
    writerLicense.write(license, IOFormat.BINARY)
  }

  def writeKey(keyPair: LicenseKeyPair, idCompany: String): Unit = {
    logger.debug("record keys to file")
    val writerKey = new KeyPairWriter(s"private-${idCompany}", s"public-${idCompany}")
    writerKey.write(keyPair, IOFormat.BINARY)
  }

  def main(args: Array[String]): Unit = {
    val parser = new DefaultParser
    writeLicence(createLicence(parser.parse(options, args)))
  }
}
