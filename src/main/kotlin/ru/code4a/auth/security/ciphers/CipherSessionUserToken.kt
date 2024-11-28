package ru.code4a.auth.security.ciphers

import jakarta.annotation.PostConstruct
import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.inject.ConfigProperty
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.security.SecureBytesGeneratorStrong
import ru.code4a.auth.security.ciphers.aescbc.CipherAESCBCIVMSG
import ru.code4a.auth.security.ciphers.aesecb.CipherAESECB
import ru.code4a.auth.security.ciphers.aesgcm.CipherAESGCMIVMSG
import ru.code4a.auth.security.ciphers.chacha20poly1305.CipherChaCha20Poly1305IVMSG
import ru.code4a.auth.utils.toByteArray
import kotlin.math.min

@ApplicationScoped
class CipherSessionUserToken(
  private val cipherAESGCMIVMSG: CipherAESGCMIVMSG,
  private val cipherAESCBCIVMSG: CipherAESCBCIVMSG,
  private val cipherChaCha20Poly1305IVMSG: CipherChaCha20Poly1305IVMSG,
  private val cipherAESECB: CipherAESECB,
  private val decoderBase64: DecoderBase64,
  private val secureBytesGeneratorStrong: SecureBytesGeneratorStrong
) {

  @ConfigProperty(name = "foura.fauth.secret-session-user-token-key-base64")
  private lateinit var secretSessionUserTokenKeyBase64: String

  @ConfigProperty(name = "foura.fauth.secret-session-user-token-id-key-256bit-base64")
  private lateinit var secretSessionUserTokenIdKey256bitBase64: String

  private lateinit var secretSessionUserTokenIdKey128bitsRounds: ArrayList<ByteArray>

  private lateinit var secretKeyBytesRounds: ArrayList<ByteArray>

  @PostConstruct
  protected fun init() {
    val secretKeyBytes = decoderBase64.decode(secretSessionUserTokenKeyBase64)

    if (secretKeyBytes.size != 96) {
      throw IllegalArgumentException("Secret Server Session Key must be 96 bytes")
    }

    secretKeyBytesRounds = divideDataIntoChunks(secretKeyBytes, 32)

    val secretSessionUserTokenIdKeyRounds = decoderBase64.decode(secretSessionUserTokenIdKey256bitBase64)

    if (secretSessionUserTokenIdKeyRounds.size != 32) {
      throw IllegalArgumentException("Secret Server Session Key Id must be 32 bytes")
    }

    secretSessionUserTokenIdKey128bitsRounds = divideDataIntoChunks(secretSessionUserTokenIdKeyRounds, 16)
  }

  private val ivAESLengthBits = 128
  private val ivChaChaLengthBits = 12 * 8

  private val saltSizeBytes = 1

  fun encrypt(sessionTokenId: Long, data: ByteArray): ByteArray {
    /**
     * Prepare iv
     */
    val sessionTokenAESECBEncrypted128bitsRound1 =
      cipherAESECB.encrypt(
        sessionTokenId.toByteArray() + secureBytesGeneratorStrong.generate(8),
        secretSessionUserTokenIdKey128bitsRounds[0]
      )

    val sessionTokenAESECBEncrypted128bitsRound2 =
      cipherAESECB.encrypt(
        sessionTokenId.toByteArray() + secureBytesGeneratorStrong.generate(8),
        secretSessionUserTokenIdKey128bitsRounds[1]
      )

    /**
     * Rounds
     */
    val round1 =
      cipherAESGCMIVMSG.encryptWithIV(
        data,
        secretKeyBytesRounds[0],
        iv = sessionTokenAESECBEncrypted128bitsRound1,
        saltSizeBytes = saltSizeBytes
      )

    val round2 =
      cipherAESCBCIVMSG.encryptWithIV(
        round1,
        secretKeyBytesRounds[1],
        iv = sessionTokenAESECBEncrypted128bitsRound2,
        saltSizeBytes = saltSizeBytes
      )

    val round3 =
      cipherChaCha20Poly1305IVMSG.encrypt(
        round2,
        secretKeyBytesRounds[2],
        ivLengthBits = ivChaChaLengthBits,
        saltSizeBytes = saltSizeBytes
      )

    val reserved =
      ByteArray(1) {
        0
      }

    return reserved + round3
  }

  fun decrypt(dataRaw: ByteArray): ByteArray {
    // remove reserved byte
    val data = dataRaw.copyOfRange(1, dataRaw.size)

    val round1 =
      cipherChaCha20Poly1305IVMSG.decrypt(
        data,
        secretKeyBytesRounds[2],
        ivLengthBits = ivChaChaLengthBits,
        saltSizeBytes = saltSizeBytes
      )

    val round2 =
      cipherAESCBCIVMSG.decrypt(
        round1,
        secretKeyBytesRounds[1],
        ivLengthBits = ivAESLengthBits,
        saltSizeBytes = saltSizeBytes
      )

    val round3 =
      cipherAESGCMIVMSG.decrypt(
        round2,
        secretKeyBytesRounds[0],
        ivLengthBits = ivAESLengthBits,
        saltSizeBytes = saltSizeBytes
      )

    return round3
  }

  private fun divideDataIntoChunks(
    source: ByteArray,
    chunkSize: Int
  ): ArrayList<ByteArray> {
    val result: ArrayList<ByteArray> = ArrayList()
    if (chunkSize <= 0) {
      result.add(source)
    } else {
      for (chunk in source.indices step chunkSize) {
        result.add(source.copyOfRange(chunk, min(chunk + chunkSize, source.size)))
      }
    }
    return result
  }
}
