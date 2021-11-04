package in.vojt.loonyssh

import com.jcraft.jsch.jce.SHA256
import com.jcraft.jsch.Buffer
import com.jcraft.jsch.Exposed
import com.jcraft.jsch.jce.AES128CTR
import com.jcraft.jsch.jce.HMACSHA256
import com.jcraft.jsch.ExposedBuffer
import com.jcraft.jsch.HASH
import com.jcraft.jsch.Util

import java.awt.Font
import java.net.*
import java.io.*
import scala.io.Source
import java.nio.ByteBuffer
import java.util.Locale
import scala.deriving.*
import scala.compiletime.*
import scala.reflect.ClassTag
import java.util.Random
// import scala.deriving.constValue
import com.jcraft.jsch.jce.ECDHN
import com.jcraft.jsch.DHEC256
import com.jcraft.jsch.DHECN
import com.jcraft.jsch.jce.SHA256
import com.jcraft.jsch.jce.SignatureRSA

val ClientName = "LoonySSH"
val ClientVersion = "0.0.1"
val IdentificationString = s"SSH-2.0-${ClientName}_${ClientVersion}\r\n"

def kexClient() = SSHMsg.KexInit(
    cookie = FixedSizeList[4, Int](List.fill(4)(4)),
    kexAlgorithms = NameList(List(KeyExchangeMethod.`ecdh-sha2-nistp256`)),
    serverHostKeyAlgorithms = NameList(List(PublicKeyAlgorithm.`ssh-rsa`)),
    encryptionAlgorithmsClientToServer = NameList(List(EncryptionAlgorithm.`aes128-ctr`)),
    encryptionAlgorithmsServerToClient = NameList(List(EncryptionAlgorithm.`aes128-ctr`)),
    macAlgorithmsClientToServer = NameList(List(MACAlgorithm.`hmac-sha2-256`)),
    macAlgorithmsServerToClient = NameList(List(MACAlgorithm.`hmac-sha2-256`)),
    compressionAlgorithmsClientToServer = NameList(List(CompressionAlgorithm.`none`)),
    compressionAlgorithmsServerToClient = NameList(List(CompressionAlgorithm.`none`)),
    languagesClientToServer = NameList(List()),
    languagesServerToClient = NameList(List()),
    kexFirstPacketFollows = 0,
    reserved = 0,
)

implicit val ctx: SSHContext = SSHContext()

// implement the required ssh-dss
def verify(H: Array[Byte], sig_of_H: Array[Byte]): SSHReader[Boolean] = for
    alg <- SSHReader[String]
    _ = assert(alg == "ssh-rsa")
    ee <- SSHReader[Array[Byte]]
    n <- SSHReader[Array[Byte]]
yield {
    val sig = new SignatureRSA()
    sig.init()
    sig.setPubKey(ee, n)
    sig.update(H)
    sig.verify(sig_of_H)
}

// replace as much jsch logic as possible with the JVM builtin cypher stuff

val sshProtocol = for
    vC <- SSHWriter.plain(new Transport.Identification(IdentificationString))
    vS <- SSHReader[Transport.Identification]
    bpKexClient <- SSHWriter.overBinaryProtocol(kexClient())
    (kexServer, bpKexServer) <- SSHReader.fromBinaryProtocol[SSHMsg.KexInit](mac = false)
    // TODO negotiate intead of assuming XDH / X25519
    (ecdh, qC) <- {
        // https://datatracker.ietf.org/doc/html/rfc5656#section-4

        val ecdh = new ECDHN()
        ecdh.init(256)
        val qC = ecdh.getQ

        SSHWriter.
          overBinaryProtocol(SSHMsg.KexECDHInit(qC)).
          map(_ => (ecdh, qC))
    }
    (ecdhReply, ecdhBp) <- SSHReader.fromBinaryProtocol[SSHMsg.KexECDHReply](mac = false)
    sshContext <- {
        val rs = Exposed.fromPoint(ecdhReply.qS)
        assert(ecdh.validate(rs(0), rs(1)))

        // DHECN.normalize
        // what the hell is the initial 0?
        val K = ecdh.getSecret(rs(0), rs(1))
        val sigofH = ecdhReply.signature
        val sha256 = new SHA256()
        sha256.init()

        val buf = new Buffer()
        buf.putString(vC.version.trim.getBytes) // string   V_C, client's identification string (CR and LF excluded)
        buf.putString(vS.version.trim.getBytes) // string   V_S, server's identification string (CR and LF excluded)
        buf.putString(Array(bpKexClient.magic) ++ bpKexClient.payload) // string   I_C, payload of the client's SSH_MSG_KEXINIT
        buf.putString(Array(bpKexServer.magic) ++ bpKexServer.payload) // string   I_S, payload of the server's SSH_MSG_KEXINIT
        buf.putString(ecdhReply.kS) // string   K_S, server's public host key
        buf.putString(qC) // string   Q_C, client's ephemeral public key octet string
        buf.putString(ecdhReply.qS) // string   Q_S, server's ephemeral public key octet string
        buf.putMPInt(K) // mpint    K__,   shared secret
        val foo = new Array[Byte](buf.getLength)
        buf.getByte(foo)
        sha256.update(foo, 0, foo.length)
        val H = sha256.digest

        SSHReader.pure(
            verify(H, sigofH).read(BinaryProtocol(ByteBuffer.wrap(ecdhReply.kS))).left.map {
                _ => Err.Oth("Failed to verify kex")
            }
        ).map(_ => {
            val cypherC2S = new AES128CTR()
            val cypherS2C = new AES128CTR()

            val macC2S = new HMACSHA256()
            val macS2C = new HMACSHA256()

            def hash(sep: Byte): Array[Byte] = {
                val buf = new ExposedBuffer()
                sha256.init()
                buf.putMPInt(K)
                buf.putByte(H)
                buf.putByte(sep)
                buf.putByte(H)
                sha256.update(buf.getBuffer, 0, buf.getIndex)
                sha256.digest()
            }

            val ivC2S = hash('A') // Initial IV client to server:     HASH (K || H || "A" || session_id)
            val ivS2C = hash('B') // Initial IV server to client:     HASH (K || H || "B" || session_id)
            val ecC2S = hash('C') // Encryption key client to server: HASH (K || H || "C" || session_id)
            val ecS2C = hash('D') // Encryption key server to client: HASH (K || H || "D" || session_id)
            val ikC2S = hash('E') // Integrity key client to server:  HASH (K || H || "E" || session_id)
            val ikS2C = hash('F') // Integrity key server to client:  HASH (K || H || "F" || session_id)

            /*
             *   K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
             *   K2 = HASH(K || H || K1)
             *   K3 = HASH(K || H || K1 || K2)
             *   ...
             *   key = K1 || K2 || K3 || ...
             */
            def expandKey(key: Array[Byte], requiredLength: Int): Array[Byte] = {
                val buf = new ExposedBuffer()
                val blockSize = sha256.getBlockSize
                buf.reset()
                buf.putMPInt(K)
                buf.putByte(H)

                sha256.init()
                sha256.update(buf.getBuffer, 0, buf.getIndex)

                def loop(length: Int, previous: Array[Byte]): List[Array[Byte]] = {
                    if (length > requiredLength) {
                        Nil
                    } else {
                        sha256.update(previous, 0, previous.length)
                        val current = sha256.digest()
                        current :: loop(length + blockSize, current)
                    }
                }

                (key :: loop(buf.getIndex, key)).toArray.flatten
            }

            macC2S.init(expandKey(ikC2S, macC2S.getBlockSize))
            macS2C.init(expandKey(ikS2C, macS2C.getBlockSize))

            cypherC2S.init(0, ecC2S, ivC2S)
            cypherS2C.init(1, ecS2C, ivS2C)

            SSHContext(Some(H), Some(sha256), Some(cypherC2S), Some(cypherS2C), Some(macC2S), Some(macS2C))
        })
    }
    _ <- SSHWriter.overBinaryProtocol(SSHMsg.NewKeys)
    _ <- SSHReader.fromBinaryProtocol[SSHMsg.NewKeys.type](mac = false)
    encrypted <- {
        implicit val ctx:SSHContext = sshContext
        val msg = SSHMsg.ServiceRequest(Service.`ssh-userauth`)
        val errOrPacket = for
            binary <- SSHWriter.transport[SSHMsg.ServiceRequest](msg)
        yield
            Transport.encrypt(binary)
            
        for
            packet: Transport.EncryptedPacket <- SSHReader.pure(errOrPacket)
            _ <- SSHWriter.send(packet)
        yield
            packet
    }
//    _ <- SSHWriter.overBinaryProtocol()
// _ <- read NewKeys = 21
// _ <- write ServiceRequest = 5
// _ <- read ServiceAccept = 6
// _ <- write UserauthRequest = 50
// _ <- read UserauthFailure = 51 | UserauthSuccess = 52
yield
    encrypted

def negotiate(server: SSHMsg.KexInit, client: SSHMsg.KexInit): SSHMsg.KexInit =
    val kexAlgorithm = client.kexAlgorithms.find(client.kexAlgorithms.contains)
    ???


def connect(bis: BufferedInputStream, bos: BufferedOutputStream) =
    val errOrRes = sshProtocol.read(BinaryProtocol(bis, bos))
    errOrRes match {
        case Right(res) => println(s"RESULT: $res")
        case Left(Err.Exc(e)) => throw e
        case Left(o) => System.err.println(o)
    }

    //  import com.jcraft.jsch.jce.AES128CTR
    //  import com.jcraft.jsch.{DHEC256, Utils, WrapperIO, WrapperSession}
    //  val dh = new DHEC256(ident.getBytes, IdentificationString.getBytes, ???, ???)
    //  dh.init(sess)

    println("Pause:")
    Thread.sleep(3000)

    println("Remaining:")
    LazyList.continually(bis.read).
      map(c => f"${c.toByte}%02X-").
      take(50).
      foreach(print)

    println("Finished!")


@main def Main(): Unit =
    val soc = new Socket("localhost", 2200)

    val bis = new BufferedInputStream(soc.getInputStream)
    val bos = new BufferedOutputStream(soc.getOutputStream)

    try
        connect(bis, bos)
    finally
        bos.flush()
        soc.close()