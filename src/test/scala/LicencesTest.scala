import Licences._
import javax0.license3j.io.{IOFormat, KeyPairReader, LicenseReader}
import org.scalatest.FunSuite
import org.scalatest.Matchers.convertNumericToPlusOrMinusWrapper

import java.io.File
import java.util.Date

class LicencesTest extends FunSuite {

  def slashSelection(): Char = {
    s"${System.getProperty("user.dir")}" match {
      case x if x.contains(s"\\") => '\\'
      case x if x.contains("/") => '/'
    }
  }

  def testFileDelete(companyId: String): Unit = {
    val slash = slashSelection()
    new File(companyId + slash + s"private-${companyId}").delete()
    new File(companyId + slash + s"public-${companyId}").delete()
    new File(companyId + slash + s"license-${companyId}").delete()
    new File(companyId).delete()
  }

  test("Checking the string from the getInformation function") {
    assert(getInformation === "\nTo output help, run the jar file without parameters\n")
  }

  test("Public key length") {
    assert(createKeyPair("RSA", 512).getPublic.length === 98)
  }

  test("Private key length") {
    assert(createKeyPair("RSA", 512).getPrivate.length === (349 +- 2))
  }

  test("Private key is unique") {
    assert(createKeyPair("RSA", 512).getPair.getPrivate !==
      createKeyPair("RSA", 512).getPair.getPrivate)
  }

  test("public key is not equal to private key") {
    val keyPair = createKeyPair("RSA", 512)
    assert(keyPair.getPair.getPublic !==
      keyPair.getPair.getPrivate)
  }

  test("Public key is unique") {
    assert(createKeyPair("RSA", 512).getPair.getPublic !==
      createKeyPair("RSA", 512).getPair.getPublic)
  }

  test("Licences param. The recorded parameter is the same as the parameter taken from the license. MAU") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("mau").getInt === 10)
  }

  test("Licences param. MAU parameter taken from the license does not correspond to the parameter that was not written to it.") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("mau").getInt !== 100)
  }

  test("Licence params. The recorded parameter is the same as the parameter taken from the license. OWN") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("owner").getString === "own")
  }

  test("Licence params. OWN parameter taken from the license does not correspond to the parameter that was not written to it.") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("owner").getString !== "OWN")
  }

  test("Licences param. The recorded parameter is the same as the parameter taken from the license. DATE") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("expiryDate").getDate === new Date(10000))
  }

  test("Licences param. DATE parameter taken from the license does not correspond to the parameter that was not written to it.") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("expiryDate").getDate !== new Date(1000))
  }

  test("Get pubKey. Digest length") {
    val keys = createKeyPair("RSA", 512)
    val pubKeyString = getPubKey(keys)
    val digest = pubKeyString.takeWhile(x => x != ';')
    //example of writing bytes: (byte)0x52
    assert(digest.count(_ == 'x') === 64)
  }

  test("Get pubKey. Key length") {
    val keys = createKeyPair("RSA", 512)
    val pubKeyString = getPubKey(keys)
    val digest = pubKeyString.dropWhile(x => x != ';')
    //example of writing bytes: (byte)0x52
    assert(digest.count(_ == 'x') === 98)
  }

  test("write key") {
    val keys = createKeyPair("RSA", 512)
    val idCompany = "idCompanyTest"
    val addressDirKey = idCompany
    val addressPrivKey = s"${addressDirKey}" + slashSelection() + s"public-${idCompany}"
    writeKey(keys, idCompany)
    val keyReader = new KeyPairReader(addressPrivKey)
    val privatekey = keyReader.readPublic(IOFormat.BASE64)
    keyReader.close()
    assert(keys.getPair.getPublic === privatekey.getPair.getPublic)
    testFileDelete(idCompany)
  }
  test("write key. get private") {
    val keys = createKeyPair("RSA", 512)
    val idCompany = "idCompanyTest"
    val addressDirKey = idCompany
    val addressPrivKey = s"${addressDirKey}" + slashSelection() + s"private-${idCompany}"
    writeKey(keys, idCompany)
    val keyReader = new KeyPairReader(addressPrivKey)
    val privatekey = keyReader.readPrivate(IOFormat.BASE64)
    keyReader.close()
    assert(keys.getPair.getPrivate === privatekey.getPair.getPrivate)
    testFileDelete(idCompany)
  }

  test("write licence") {
    val companyId = "idCompanyTest"
    val keyPair = createKeyPair("RSA", 512)
    writeKey(keyPair, companyId)
    val licence = createLicence(10, companyId, new Date(10000), keyPair.getPair.getPrivate)
    writeLicence(licence)
    val licenceReader = new LicenseReader(s"${companyId}" + slashSelection() + s"license-${companyId}")
    val licenceFromFile = licenceReader.read(IOFormat.STRING)
    licenceReader.close()
    assert(licence.toString === licenceFromFile.toString)
    testFileDelete(companyId)
  }
}
