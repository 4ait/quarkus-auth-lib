package ru.code4a.auth.security.ciphers.aesecb

import jakarta.enterprise.context.ApplicationScoped
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// https://web.cs.ucdavis.edu/~rogaway/ocb/gcm.pdf
@ApplicationScoped
class CipherAESECB {
  companion object {
    private val cipher =
      ThreadLocal.withInitial {
        Cipher.getInstance("AES/ECB/NoPadding")
      }
  }

  /**
   * Input 128 bits key and block
   */
  fun encrypt(
    input: ByteArray,
    key: ByteArray
  ): ByteArray {
    val cipher = cipher.get()
    val secretKeySpec = SecretKeySpec(key, "AES")

    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)

    return cipher.doFinal(input)
  }

  /**
   * Input 128 bits key and block
   */
  fun decrypt(
    input: ByteArray,
    key: ByteArray
  ): ByteArray {
    val cipher = cipher.get()
    val secretKeySpec = SecretKeySpec(key, "AES")

    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec)

    return cipher.doFinal(input)
  }
}
