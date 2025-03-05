package ru.code4a.auth.security.ciphers.aescbc

import jakarta.enterprise.context.ApplicationScoped
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@ApplicationScoped
class CipherAESCBC {
  fun encrypt(
    input: ByteArray,
    key: ByteArray,
    iv: ByteArray
  ): ByteArray {
    val cipher = getCipher()
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
    val cipher = getCipher()
    val gcmSpec = IvParameterSpec(iv)
    val secretKeySpec = SecretKeySpec(key, "AES")

    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmSpec)

    return cipher.doFinal(input)
  }

  private fun getCipher(): Cipher {
    return Cipher.getInstance("AES/CBC/PKCS5Padding")
  }
}
