/*import com.javax0.license3j.licensor.License
import com.javax0.license3j.licensor.encrypt.PGPHelper*/
import javax0.license3j.License
import javax0.license3j.crypto.LicenseKeyPair

/*
import org.apache.commons.cli.Options
import java.io._
*/


object CreateLicences extends App{

 println("starting")
/* val b = new License().setHashAlgorithm(512)
 println(b.calculatePublicKeyRingDigest())*/
 //println(b.calculatePublicKeyRingDigest())
 //println(b.calculatePublicKeyRingDigest())

  val license = new License
  val a = LicenseKeyPair.Create.from("RSA", 512)
  println(a.getPublic)
  println(a.getPrivate)
  println(a.getPair)

  //var file = new PrintWriter(new File("C:\\Users\\r.gentuk\\IdeaProjects\\CreateLicences\\pair.txt"))
  //file.write(s"${a.getPair}")
  //val options = new Options()
  //options.addOption()

}
