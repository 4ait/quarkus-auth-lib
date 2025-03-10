package ru.code4a.auth.security.ciphers.aesgcm

import jakarta.enterprise.context.ApplicationScoped
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// https://web.cs.ucdavis.edu/~rogaway/ocb/gcm.pdf
@ApplicationScoped
class CipherAESGCM {
  fun encrypt(
    input: ByteArray,
    key: ByteArray,
    iv: ByteArray,
    ivLengthBits: Int
  ): ByteArray {
    val cipher = getCipher()
    val ivSpec = GCMParameterSpec(ivLengthBits, iv)
    val secretKeySpec = SecretKeySpec(key, "AES")

    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec)

    return cipher.doFinal(input)
  }

  fun decrypt(
    input: ByteArray,
    key: ByteArray,
    iv: ByteArray,
    ivLengthBits: Int
  ): ByteArray {
    val cipher = getCipher()
    val gcmSpec = GCMParameterSpec(ivLengthBits, iv)
    val secretKeySpec = SecretKeySpec(key, "AES")

    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmSpec)

    return cipher.doFinal(input)
  }

  private fun getCipher(): Cipher {
    return Cipher.getInstance("AES/GCM/NoPadding")
  }
}
