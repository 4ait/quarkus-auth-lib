package ru.code4a.auth.security.ciphers.aescbc

import jakarta.enterprise.context.ApplicationScoped
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@ApplicationScoped
class CipherAESCBC {
  companion object {
    private val cipher =
      ThreadLocal.withInitial {
        Cipher.getInstance("AES/CBC/PKCS5Padding")
      }
  }

  fun encrypt(
    input: ByteArray,
    key: ByteArray,
    iv: ByteArray
  ): ByteArray {
    val cipher = cipher.get()
    val ivSpec = IvParameterSpec(iv)
    val secretKeySpec = SecretKeySpec(key, "AES")

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
    val secretKeySpec = SecretKeySpec(key, "AES")

    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmSpec)

    return cipher.doFinal(input)
  }
}
