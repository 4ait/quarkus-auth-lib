package ru.code4a.auth.security.ciphers.chacha20poly1305

import jakarta.enterprise.context.ApplicationScoped
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// https://web.cs.ucdavis.edu/~rogaway/ocb/gcm.pdf
@ApplicationScoped
class CipherChaCha20Poly1305 {
  companion object {
    private val cipher =
      ThreadLocal.withInitial {
        Cipher.getInstance("ChaCha20-Poly1305")
      }
  }

  fun encrypt(
    input: ByteArray,
    key: ByteArray,
    iv: ByteArray
  ): ByteArray {
    val cipher = cipher.get()
    val ivSpec = IvParameterSpec(iv)
    val secretKeySpec = SecretKeySpec(key, "ChaCha20")

    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec)

    return cipher.doFinal(input)
  }

  fun decrypt(
    input: ByteArray,
    key: ByteArray,
    iv: ByteArray
  ): ByteArray {
    val cipher = cipher.get()
    val gcmSpec = IvParameterSpec(iv)
    val secretKeySpec = SecretKeySpec(key, "ChaCha20")

    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmSpec)

    return cipher.doFinal(input)
  }
}
