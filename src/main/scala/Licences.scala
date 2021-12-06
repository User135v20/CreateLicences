import com.typesafe.scalalogging.Logger
import javax0.license3j.{Feature, License}
import javax0.license3j.crypto.LicenseKeyPair
import javax0.license3j.io.{IOFormat, KeyPairReader, KeyPairWriter, LicenseWriter}

import java.text.SimpleDateFormat
import org.apache.commons.cli._

import java.io.{File, FileNotFoundException}
import java.nio.file.{Files, Paths}
import java.security.{MessageDigest, PrivateKey, PublicKey}
import java.util.Date

object Licences {

  class NotValidDataException extends RuntimeException
  class FolderError extends RuntimeException

  def information(): Unit = {
    System.out.println("\nTo output help, run the jar file without parameters\n")
  }

  def helper(): Unit = {
    val formatter = new HelpFormatter
    formatter.printHelp("CreateLicences", options)
  }
  val logger = Logger("CreateLicences")

  private val SCENARIOS = "s"
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
  options.addOption(SCENARIOS, true, "usage scenario: \n" +
    "1. Creating a private key/ public key pair and" +
    " output of the public key in java code format.\nRequired parameters: > company id.\n.\n" +
    "2. Creating a license file. \nRequired parameters: > company id,\n" +
    ".                    > number of active users,\n" +
    ".                    > expire date,\n " +
    ".                    > private key.")
  options.addOption(MAU, true, "number of active users per month")
  options.addOption(OWN, true, "id of the company for which the license is issued")
  options.addOption(DATE, true, s"expiry date, format ${DATEFORMAT}")

  def parsingMAU(cmd: CommandLine): Int = {
    val activeUsers = cmd.getOptionValue(MAU).toInt
    //logger.debug(s"parse ${options.getOption(MAU).getDescription}: ${activeUsers}")
    activeUsers
  }

  def parsingOWN(cmd: CommandLine): String = {
    val owner = cmd.getOptionValue(OWN)
    //logger.debug(s"parse ${options.getOption(OWN).getDescription}: ${owner}")
    owner
  }

  def parsingDATE(cmd: CommandLine): Date = {
    val formatter = new SimpleDateFormat(DATEFORMAT)
    val rowDate = cmd.getOptionValue(DATE)
    //logger.debug(s"parse ${options.getOption(DATE).getDescription}: ${rowDate}")
    formatter.parse(rowDate)
  }

  def createKeyPair(keyCipher: String, keySize: Int): LicenseKeyPair ={
    //logger.debug("create key pair")
    LicenseKeyPair.Create.from(keyCipher, keySize)
  }

  def createLicence(mua: Int, own: String, date: Date, keyPair: LicenseKeyPair ): License ={
    //logger.debug("start of license creation")
    val license = new License

    license.setLicenseId
    //logger.debug("set license id")

    license.setExpiry(date)
    //logger.debug("set license date")

    license.add(Feature.Create.intFeature(LICENSEMAU, mua))
    //logger.debug(s"add license ${options.getOption(MAU).getDescription}")

    license.add(Feature.Create.stringFeature(LICENSEOWN, own))
    //logger.debug(s"add license ${options.getOption(OWN).getDescription}")

    license.sign(keyPair.getPair.getPrivate, LICENSEDIGEST)
  /*  logger.debug("sign license")
    logger.debug(s"license has been created:\n${license}")
   */ license
  }


  def writeLicence(license: License): Unit = {
    val idCompany = license.getFeatures.get(LICENSEOWN).getString
    val writerLicense = new LicenseWriter(s"${idCompany}/license-${idCompany}")
    writerLicense.write(license, IOFormat.STRING)
    //logger.debug("license was recorded")
  }

  def writeKey(keyPair: LicenseKeyPair, idCompany: String): Unit = {

    val path = Paths.get(s"${idCompany}")
    if (Files.exists(path)) {
      throw new FolderError
    }
    else {
      new File(s"${idCompany}").mkdir
      val writerKey = new KeyPairWriter(s"${idCompany}/private-${idCompany}", s"${idCompany}/public-${idCompany}")
      writerKey.write(keyPair, IOFormat.BASE64)
      //logger.debug("keys was recorded to file")
    }
  }

  def getPubKey(keyPair: LicenseKeyPair): Unit = {

    val key = keyPair.getPublic()
    val calculatedDigest = MessageDigest.getInstance("SHA-512").digest(key)

    def convertToJavaCode(i: Int, maxIndex: Int, str: String, f: Int => Int): String = {

      def bytesToString(i: Int): String = String.format("(byte)0x%02X, ",(f(i) & 0xff))

      i match {
        case x if (x < maxIndex ) =>
          if (x % 8 == 0)
           convertToJavaCode(i+1, maxIndex, str +  bytesToString(i) + "\n", f)
          else
            convertToJavaCode(i+1, maxIndex, str + bytesToString(i), f)
        case _ => str
      }
    }
    val  pubKeyString = "--KEY DIGEST START\nbyte [] digest = new byte[] {\n" +
      convertToJavaCode(0, calculatedDigest.length, "", x => calculatedDigest(x)) +
      "\n};\n---KEY DIGEST END\n" +
      "--KEY START\nbyte [] key = new byte[] {\n" +
        convertToJavaCode(0, key.length,  "", x => key(x)) +
        "\n};\n---KEY END\n"
//    logger.debug(s"public key: \n${pubKeyString}")
    System.out.println(pubKeyString)
  }

  def main(args: Array[String]): Unit = {

    val parser = new DefaultParser
    try {
      val cmd = parser.parse(options, args)
      if (cmd.hasOption(SCENARIOS)) {
        val scenarios = cmd.getOptionValue(SCENARIOS).toInt
        if ((scenarios == 1 | scenarios == 2) &
          ((cmd.hasOption(OWN)) | (cmd.hasOption(MAU) & cmd.hasOption(OWN) & cmd.hasOption(DATE)))) {
          if (scenarios == 1) {
            val own = parsingOWN(cmd)
            if (own.nonEmpty) {
              val keyPair = createKeyPair(KEYCIPHER, KEYSIZE)
              writeKey(keyPair, own)
              System.out.println("PUBLIC KEY")
              getPubKey(keyPair)
            }
            else
              throw new NullPointerException
          }
          else {
            val own = parsingOWN(cmd)
            val mua = parsingMAU(cmd)
            val date = parsingDATE(cmd)
            val keyReader = new KeyPairReader(s"${own}/private-${own}")
            val privatekey = keyReader.readPrivate(IOFormat.BASE64)

            if (date.after(new Date(System.currentTimeMillis())) & mua > 0) {
              writeLicence(createLicence(mua, own, date, privatekey))
              System.out.println("The license was created and written to a file")
            } else
              throw new NotValidDataException()
          }
        }
      }
      else {
        helper()
      }
    }
    catch {
      case ex: FolderError =>
        logger.error("the folder with the specified company ID already exists")
        information()
      case ex: NotValidDataException =>
        logger.error(s"expire date is not valid")
        information()
      case ex: NumberFormatException =>
        logger.error(s"error parsing the usage scenario parameter or the number of active users parameter")
        information()
      case ex: java.text.ParseException =>
        logger.error(s"Error parsing ${options.getOption(DATE).getDescription}")
        information()
      case ex: NullPointerException =>
        logger.error(s"Error parsing ${options.getOption(OWN).getDescription} or ${options.getOption(DATE).getDescription}")
        information()
      case ex: MissingArgumentException =>
        logger.error("There are not enough input parameters")
        information()
      case ex: IllegalArgumentException =>
        logger.error(s"Invalid key format")
        information()
      case ex: FileNotFoundException =>
        logger.error(s"There is no private key for the company")
        information()
    }
  }
}