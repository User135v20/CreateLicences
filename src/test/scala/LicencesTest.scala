import Licences._
import org.scalatest.FunSuite
import org.scalatest.Matchers.convertNumericToPlusOrMinusWrapper
import java.util.Date

class LicencesTest extends FunSuite {


  test("Public key length") {
    assert(createKeyPair("RSA", 512).getPublic.length === 98)
  }

  test("Private key length") {
    assert(createKeyPair("RSA", 512).getPrivate.length === (349 +- 1))
  }

  test("Private key is unique") {
    assert(createKeyPair("RSA", 512).getPair.getPrivate !==
      createKeyPair("RSA", 512).getPair.getPrivate)
  }

  test("Public key is unique") {
    assert(createKeyPair("RSA", 512).getPair.getPublic !==
      createKeyPair("RSA", 512).getPair.getPublic)
  }

  test("Licences param. MAU") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("mau").getInt === 10)
  }

  test("Licences param.unequal MAU") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("mau").getInt !== 100)
  }

  test("Licence params. OWN") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("owner").getString === "own")
  }

  test("Licence params. unequal OWNS") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("owner").getString !== "OWN")
  }

  test("Licences param. DATE") {
    val privateKey = createKeyPair("RSA", 512).getPair.getPrivate
    val licence = createLicence(10, "own", new Date(10000), privateKey)
    assert(licence.getFeatures.get("expiryDate").getDate === new Date(10000))
  }

  test("Licences param. unequal DATES") {
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
}
