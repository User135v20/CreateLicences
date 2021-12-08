import com.typesafe.scalalogging.Logger
import javax0.license3j.crypto.LicenseKeyPair
import javax0.license3j.io.{IOFormat, KeyPairReader, KeyPairWriter, LicenseWriter}
import javax0.license3j.{Feature, License}
import org.apache.commons.cli._

import java.io.{File, FileNotFoundException}
import java.nio.file.{Files, Paths}
import java.security.{MessageDigest, PrivateKey}
import java.text.SimpleDateFormat
import java.util.Date

object Licences {

  class NotValidDateException extends RuntimeException

  class DateHasAlreadyExpiredException extends RuntimeException

  class PrivKeyAlreadyExistsException extends RuntimeException

  class EmptyOwnException extends RuntimeException

  def getInformation(): String = {
    "\nTo output help, run the jar file without parameters\n"
  }

  def helper(): Unit = {
    val formatter = new HelpFormatter
    formatter.printHelp("CreateLicences", options).toString
  }

  val logger = Logger("CreateLicences")

  private val KEYS = "k"
  private val MAU = "m"
  private val OWN = "o"
  private val DATE = "d"

  private val DATEFORMAT = "yyyy-mm-dd hh:mm:ss"
  private val KEYCIPHER = "RSA"
  private val KEYSIZE = 512
  private val LICENSEDIGEST = "SHA"
  private val LICENSEOWN = "owner"
  private val LICENSEMAU = "mau"
  private val ADDRESSSLASH = s"${System.getProperty("user.dir")}" match {
    case x if x.contains(s"\\") => s"\\"
    case x if x.contains("/") => "/"
  }
  private val WORKINGDIRECTORYADDRESS = System.getProperty("user.dir") + ADDRESSSLASH

  val options = new Options
  options.addOption("", false, "usage scenario: \n" +
    "1. Creating a private key/ public key pair and" +
    " output of the public key in java code format.\nRequired parameters: > company id.\n" +
    ".                    > flag generate-keys\n" +
    "2. Creating a license file. \nRequired parameters: > number of active users,\n" +
    ".                    > expire date,\n" +
    ".                    > company id.\n \n . ")
  options.addOption(MAU, true, "number of active users per month")
  options.addOption(OWN, true, "id of the company for which the license is issued")
  options.addOption(DATE, true, s"expiry date, format ${DATEFORMAT}")
  options.addOption(KEYS, false, "use this parameter if you want to create keys")

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

  def createKeyPair(keyCipher: String, keySize: Int): LicenseKeyPair = {
    //logger.debug("create key pair")
    LicenseKeyPair.Create.from(keyCipher, keySize)
  }

  def createLicence(mua: Int, own: String, date: Date, privateKey: PrivateKey): License = {
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

    license.sign(privateKey, LICENSEDIGEST)
    /*  logger.debug("sign license")
      logger.debug(s"license has been created:\n${license}")*/
    license
  }

  def writeLicence(license: License): Unit = {
    val idCompany = license.getFeatures.get(LICENSEOWN).getString
    val writerLicense = new LicenseWriter(s"${idCompany}/license-${idCompany}")
    writerLicense.write(license, IOFormat.STRING)
    //logger.debug("license was recorded")
    System.out.println(s"The license was created and written to a file license-${idCompany} " +
      s"\nin folder: ${WORKINGDIRECTORYADDRESS + idCompany}")
  }

  def writeKey(keyPair: LicenseKeyPair, idCompany: String): Unit = {

    val pathPrivate = Paths.get(s"${idCompany}/private-${idCompany}")
    if (Files.exists(pathPrivate)) {
      logger.error(s"There are already keys in the folder \n${WORKINGDIRECTORYADDRESS + idCompany}")
      throw new PrivKeyAlreadyExistsException
    }
    else {
      new File(s"${idCompany}").mkdir
      val writerKey = new KeyPairWriter(s"${idCompany}${ADDRESSSLASH}private-${idCompany}", s"${idCompany}${ADDRESSSLASH}public-${idCompany}")
      writerKey.write(keyPair, IOFormat.BASE64)
      System.out.println(s"Keys were written to a files private-${idCompany} and public-${idCompany} \nin the folder ${WORKINGDIRECTORYADDRESS + idCompany}")
    }
  }

  def getPubKey(keyPair: LicenseKeyPair): String = {

    val key = keyPair.getPublic()
    val calculatedDigest = MessageDigest.getInstance("SHA-512").digest(key)

    def convertToJavaCode(i: Int, maxIndex: Int, str: String, f: Int => Int): String = {

      def bytesToString(i: Int): String = String.format("(byte)0x%02X, ", (f(i) & 0xff))

      i match {
        case x if (x < maxIndex) =>
          if (x % 8 == 0)
            convertToJavaCode(i + 1, maxIndex, str + bytesToString(i) + "\n", f)
          else
            convertToJavaCode(i + 1, maxIndex, str + bytesToString(i), f)
        case _ => str
      }
    }

    "--KEY DIGEST START\nbyte [] digest = new byte[] {\n" +
      convertToJavaCode(0, calculatedDigest.length, "", x => calculatedDigest(x)) +
      "\n};\n---KEY DIGEST END\n" +
      "--KEY START\nbyte [] key = new byte[] {\n" +
      convertToJavaCode(0, key.length, "", x => key(x)) +
      "\n};\n---KEY END\n"
  }

  def main(args: Array[String]): Unit = {

    val parser = new DefaultParser
    try {
      val cmd = parser.parse(options, args)
      cmd match {
        case x if (!(x.hasOption(KEYS) || x.hasOption(MAU) || x.hasOption(DATE) || x.hasOption(OWN))) =>
          helper()

        case x if (x.hasOption(KEYS)) =>
          val own = parsingOWN(cmd)
          if (cmd.hasOption(OWN) && own != None) {
            val keyPair = createKeyPair(KEYCIPHER, KEYSIZE)
            writeKey(keyPair, own)
            System.out.println("PUBLIC KEY")
            System.out.println(getPubKey(keyPair))
          }
          else
            throw new EmptyOwnException

        case _ =>
          val own = parsingOWN(cmd)
          val mua = parsingMAU(cmd)
          val date = parsingDATE(cmd)

          if (mua > 0)
            if (own != None)
              if (date.after(new Date(System.currentTimeMillis()))) {
                val keyReader = new KeyPairReader(s"${own}${ADDRESSSLASH}private-${own}")
                val privatekey = keyReader.readPrivate(IOFormat.BASE64)
                writeLicence(createLicence(mua, own, date, privatekey.getPair.getPrivate))
              }
              else throw new DateHasAlreadyExpiredException
            else throw new EmptyOwnException
          else throw new NumberFormatException
      }
    }
    catch {
      case ex: PrivKeyAlreadyExistsException =>
        System.out.println(getInformation())
      case ex: DateHasAlreadyExpiredException =>
        logger.error("Date has already expired")
        System.out.println(getInformation())
      case ex: NotValidDateException =>
        logger.error(s"expire date is not valid")
        System.out.println(getInformation())
      case ex: NumberFormatException =>
        logger.error(s"error parsing the number of active users parameter")
        System.out.println(getInformation())
      case ex: java.text.ParseException =>
        logger.error(s"Error parsing ${options.getOption(DATE).getDescription}")
        System.out.println(getInformation())
      case ex: EmptyOwnException =>
        logger.error(s"Error parsing ${options.getOption(OWN).getDescription}")
        System.out.println(getInformation())
      case ex: NullPointerException =>
        logger.error(s"Error parsing ${options.getOption(DATE).getDescription}")
        System.out.println(getInformation())
      case ex: UnrecognizedOptionException =>
        logger.error("Invalid command entered")
        System.out.println(getInformation())
      case ex: MissingArgumentException =>
        logger.error("There are not enough input parameters")
        System.out.println(getInformation())
      case ex: IllegalArgumentException =>
        logger.error(s"Invalid key format")
        System.out.println(getInformation())
      case ex: FileNotFoundException =>
        logger.error(s"There is no private key for the company")
        System.out.println(getInformation())
    }
  }
}