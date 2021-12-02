import com.typesafe.scalalogging.Logger
import javax0.license3j.{Feature, License}
import javax0.license3j.crypto.LicenseKeyPair
import javax0.license3j.io.{IOFormat, KeyPairWriter, LicenseWriter}

import java.text.SimpleDateFormat
import org.apache.commons.cli.{CommandLine, DefaultParser, MissingArgumentException, Options}

import java.security.PublicKey
import java.util.Date

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
  private val LICENSEDATE = "expiryDate"

  val options = new Options
  options.addOption(MAU, true, "number of active users per month")
  options.addOption(OWN, true, "id of the company for which the license is issued")
  options.addOption(DATE, true, s"expiry date. format ${DATEFORMAT}")

  def parsingMAU( cmd: CommandLine): Int = {
    try {
      val activeUsers = cmd.getOptionValue(MAU).toInt
      logger.debug(s"parse ${options.getOption(MAU).getDescription}: ${activeUsers}")
      activeUsers
    } catch {
      case ex: NumberFormatException =>
        logger.error(s"Error parsing number of active users per month")
        -1
    }
  }

  def parsingOWN(cmd: CommandLine): String = {
    val owner = cmd.getOptionValue(OWN)
    logger.debug(s"parse ${options.getOption(OWN).getDescription}: ${owner}")
    owner
  }

  def parsingDATE(cmd: CommandLine): Date = {
    val formatter = new SimpleDateFormat(DATEFORMAT)
    val rowDate = cmd.getOptionValue(DATE)
    logger.debug(s"parse ${options.getOption(DATE).getDescription}: ${rowDate}")
    try {
      formatter.parse(rowDate)}
    catch {
      case ex: java.text.ParseException =>
        logger.error(s"Error parsing ${options.getOption(DATE).getDescription}")
        new Date(0)
      case ex: NullPointerException =>
        logger.error(s"Error parsing ${options.getOption(DATE).getDescription}")
        new Date(0)
    }
  }

  def createKeyPair(keyCipher: String, keySize: Int): LicenseKeyPair ={
    logger.debug("create key pair")
    LicenseKeyPair.Create.from(keyCipher, keySize)
  }

  def createLicence(cmd: CommandLine, keyPair: LicenseKeyPair ): License ={
    logger.debug("start of license creation")
    val license = new License

    license.setLicenseId
    logger.debug("set license id")

    license.setExpiry(parsingDATE(cmd))
    logger.debug("set license date")

    license.add(Feature.Create.intFeature(LICENSEMAU, parsingMAU(cmd)))
    logger.debug(s"add license ${options.getOption(MAU).getDescription}")

    val idCompany = parsingOWN(cmd)
    try {
      license.add(Feature.Create.stringFeature(LICENSEOWN, idCompany))
      logger.debug(s"add license ${options.getOption(OWN).getDescription}")
    }
    catch {
      case ex: NullPointerException =>
        license.add(Feature.Create.stringFeature(LICENSEOWN, ""))
        logger.error(s"Error parsing ${options.getOption(OWN).getDescription}")
    }

    (license.getFeatures.get(LICENSEMAU).getInt,
      (license.getFeatures.get(LICENSEDATE).getDate,
        license.getFeatures.get(LICENSEOWN).getString)) match {
      case (x, (y, z)) if (x <= 0 | y.before(new Date(System.currentTimeMillis())) | z.length == 0) =>
        logger.error("the license was not created")
        null
      case _ =>
        license.sign(keyPair.getPair().getPrivate(), LICENSEDIGEST)
        logger.debug("sign license")
        logger.debug(s"license has been created:\n${license}")
        license
    }
  }

  def writeLicenceAndKey(keyPair: LicenseKeyPair, license: License): Unit = {
    license match {
      case x: License =>
        writeLicence(license)
        writeKey(keyPair, license.getFeatures.get(LICENSEOWN).getString)
      case _ => logger.error("license and keys was not recorded")
    }
  }

  def writeLicence(license: License): Unit = {
    val writerLicense = new LicenseWriter(s"license-${license.getFeatures.get(LICENSEOWN).getString}")
    writerLicense.write(license, IOFormat.BASE64)
    logger.debug("license was recorded")
  }

  def writeKey(keyPair: LicenseKeyPair, idCompany: String): Unit = {
    val writerKey = new KeyPairWriter(s"private-${idCompany}", s"public-${idCompany}")
    writerKey.write(keyPair, IOFormat.BASE64)
    logger.debug("keys was recorded to file")
  }

  def getPubKey(keyPair: LicenseKeyPair): PublicKey = {
    keyPair.getPair().getPublic()
  }

  def main(args: Array[String]): Unit = {

    val parser = new DefaultParser
    try {
      val cmd = parser.parse(options, args)
      val keyPair = createKeyPair(KEYCIPHER,KEYSIZE)
      writeLicenceAndKey(keyPair, createLicence(cmd,keyPair))
      //logger.debug(s"public key: \n${getPubKey(keyPair)}")
    }
    catch {
      case ex: MissingArgumentException =>
        logger.error("there are not enough input parameters")
    }
  }
}