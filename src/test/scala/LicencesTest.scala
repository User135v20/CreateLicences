import Licences._
import javax0.license3j.io.{IOFormat, KeyPairReader, LicenseReader}
import org.scalatest.FunSuite
import org.scalatest.Matchers.convertNumericToPlusOrMinusWrapper

import java.io.File
import java.security.Signature
import java.util.Date
import java.util.concurrent.ThreadLocalRandom

class LicencesTest extends FunSuite {

  private val SEPARATOR = File.separator
  private val CHIPER = "RSA"
  private val KEYSIZE = 1024


  def testFileDelete(companyId: String): Unit = {
    new File(companyId + SEPARATOR + s"private-${companyId}").delete()
    new File(companyId + SEPARATOR + s"public-${companyId}").delete()
    new File(companyId + SEPARATOR + s"license-${companyId}").delete()
    new File(companyId).delete()
  }

  test("Checking the string from the getInformation function") {
    assert(getInformation === "\nTo output help, run the jar file without parameters\n")
  }

  test("Public key length") {
    assert(createKeyPair(CHIPER, KEYSIZE).getPublic.length === 166)
  }

  test("Private key length") {
    assert(createKeyPair(CHIPER, KEYSIZE).getPrivate.length === (637 +- 5))
  }

  test("Private key is unique") {
    assert(createKeyPair(CHIPER, KEYSIZE).getPair.getPrivate !==
      createKeyPair(CHIPER, KEYSIZE).getPair.getPrivate)
  }

  test("public key is not equal to private key") {
    val keyPair = createKeyPair(CHIPER, KEYSIZE)
    assert(keyPair.getPair.getPublic !==
      keyPair.getPair.getPrivate)
  }

  test("Public key is unique") {
    assert(createKeyPair(CHIPER, KEYSIZE).getPair.getPublic !==
      createKeyPair(CHIPER, KEYSIZE).getPair.getPublic)
  }

  test("Licences param. The recorded parameter is the same as the parameter taken from the license. MAU") {
    val privateKey = createKeyPair(CHIPER, KEYSIZE).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("mau").getInt === 10)
  }

  test("Licences param. MAU parameter taken from the license does not correspond to the parameter that was not written to it.") {
    val privateKey = createKeyPair(CHIPER, KEYSIZE).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("mau").getInt !== 100)
  }

  test("Licence params. The recorded parameter is the same as the parameter taken from the license. OWN") {
    val privateKey = createKeyPair(CHIPER, KEYSIZE).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("owner").getString === "own")
  }

  test("Licence params. OWN parameter taken from the license does not correspond to the parameter that was not written to it.") {
    val privateKey = createKeyPair(CHIPER, KEYSIZE).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("owner").getString !== "OWN")
  }

  test("Licences param. The recorded parameter is the same as the parameter taken from the license. DATE") {
    val privateKey = createKeyPair(CHIPER, KEYSIZE).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("expiryDate").getDate === new Date(10000))
  }

  test("Licences param. DATE parameter taken from the license does not correspond to the parameter that was not written to it.") {
    val privateKey = createKeyPair(CHIPER, KEYSIZE).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("expiryDate").getDate !== new Date(1000))
  }

  test("Get pubKey. Digest length") {
    val keys = createKeyPair(CHIPER, KEYSIZE)
    val pubKeyString = getPubKey(keys)
    val digest = pubKeyString.takeWhile(x => x != ';')
    //example of writing bytes: (byte)0x52
    assert(digest.count(_ == 'x') === 64)
  }

  test("Get pubKey. Key length") {
    val keys = createKeyPair(CHIPER, KEYSIZE)
    val pubKeyString = getPubKey(keys)
    val key = pubKeyString.dropWhile(x => x != ';')
    //example of writing bytes: (byte)0x52
    assert(key.count(_ == 'x') === 166)
  }

  test("write key") {
    val keys = createKeyPair(CHIPER, KEYSIZE)
    val idCompany = "idCompanyTest"
    val addressDirKey = idCompany
    val addressPrivKey = s"${addressDirKey}" + SEPARATOR + s"public-${idCompany}"
    writeKey(keys, idCompany)
    val keyReader = new KeyPairReader(addressPrivKey)
    val privatekey = keyReader.readPublic(IOFormat.BASE64)
    keyReader.close()
    assert(keys.getPair.getPublic === privatekey.getPair.getPublic)
    testFileDelete(idCompany)
  }
  test("write key. get private") {
    val keys = createKeyPair(CHIPER, KEYSIZE)
    val idCompany = "idCompanyTest"
    val addressDirKey = idCompany
    val addressPrivKey = s"${addressDirKey}" + SEPARATOR + s"private-${idCompany}"
    writeKey(keys, idCompany)
    val keyReader = new KeyPairReader(addressPrivKey)
    val privatekey = keyReader.readPrivate(IOFormat.BASE64)
    keyReader.close()
    assert(keys.getPair.getPrivate === privatekey.getPair.getPrivate)
    testFileDelete(idCompany)
  }

  test("write licence") {
    val companyId = "idCompanyTest"
    val keyPair = createKeyPair(CHIPER, KEYSIZE)
    writeKey(keyPair, companyId)
    val licence = createLicence(10, companyId, new Date(10000), keyPair.getPair.getPrivate)
    writeLicence(licence)
    val licenceReader = new LicenseReader(s"${companyId}" + SEPARATOR + s"license-${companyId}")
    val licenceFromFile = licenceReader.read(IOFormat.STRING)
    licenceReader.close()
    assert(licence.toString === licenceFromFile.toString)
    testFileDelete(companyId)
  }


  test("validate a public and private key pair") {
    val keyPair = createKeyPair(CHIPER, KEYSIZE)
    val publicKey = keyPair.getPair.getPublic
    val privateKey = keyPair.getPair.getPrivate

    // create a challenge
    val challenge = new Array[Byte](10000)
    ThreadLocalRandom.current.nextBytes(challenge)

    // sign using the private key
    val sig: Signature = Signature.getInstance("SHA512WithRSA")
    sig.initSign(privateKey)
    sig.update(challenge)
    val signature = sig.sign

    // verify signature using the public key
    sig.initVerify(publicKey)
    sig.update(challenge)

    assert(sig.verify(signature) === true)
  }

  test("the validity of the key in the getPubKey function") {
    val keys = createKeyPair(CHIPER, KEYSIZE)
    val pubKeyString = getPubKey(keys).dropWhile(x => x != ';')

    def createArrayByte(str: String, keyList: List[Byte]): List[Byte] = {
      str match {
        case x if (!x.contains('x')) => keyList
        case _ =>
          val indexStart = str.indexOf('x') + 1
          val indexFinish = indexStart + 2
          val substringByte = str.substring(indexStart, indexFinish)
          createArrayByte(str.substring(indexFinish + 1), keyList :+ Integer.parseInt(substringByte, 16).toByte)
      }
    }
    assert(createArrayByte(pubKeyString, Nil).toArray === keys.getPublic)
  }
}
