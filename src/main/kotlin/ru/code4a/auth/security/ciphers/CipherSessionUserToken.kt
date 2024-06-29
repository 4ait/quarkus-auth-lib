package ru.code4a.auth.security.ciphers

import jakarta.annotation.PostConstruct
import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.inject.ConfigProperty
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.security.ciphers.aescbc.CipherAESCBCIVMSG
import ru.code4a.auth.security.ciphers.aesgcm.CipherAESGCMIVMSG
import ru.code4a.auth.security.ciphers.chacha20poly1305.CipherChaCha20Poly1305IVMSG
import kotlin.math.min

@ApplicationScoped
class CipherSessionUserToken(
  private val cipherAESGCMIVMSG: CipherAESGCMIVMSG,
  private val cipherAESCBCIVMSG: CipherAESCBCIVMSG,
  private val cipherChaCha20Poly1305IVMSG: CipherChaCha20Poly1305IVMSG,
  private val decoderBase64: DecoderBase64
) {
  @ConfigProperty(name = "foura.fauth.secret-session-user-token-key-base64")
  private lateinit var secretSessionUserTokenKeyBase64: String

  private lateinit var secretKeyBytesRounds: ArrayList<ByteArray>

  @PostConstruct
  protected fun init() {
    val secretKeyBytes = decoderBase64.decode(secretSessionUserTokenKeyBase64)

    if (secretKeyBytes.size != 96) {
      throw IllegalArgumentException("Secret Server Session Key must be 96 bytes")
    }

    secretKeyBytesRounds = divideDataIntoChunks(secretKeyBytes, 32)
  }

  private val ivAESLengthBits = 128
  private val ivChaChaLengthBits = 12 * 8

  private val saltSizeBytes = 1

  fun encrypt(data: ByteArray): ByteArray {
    val round1 =
      cipherAESGCMIVMSG.encrypt(
        data,
        secretKeyBytesRounds[0],
        ivLengthBits = ivAESLengthBits,
        saltSizeBytes = saltSizeBytes
      )

    val round2 =
      cipherAESCBCIVMSG.encrypt(
        round1,
        secretKeyBytesRounds[1],
        ivLengthBits = ivAESLengthBits,
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
