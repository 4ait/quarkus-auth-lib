package ru.code4a.auth.security.hasher

import jakarta.enterprise.context.ApplicationScoped
import java.security.MessageDigest

@ApplicationScoped
class HasherBytesSHA512 : HasherBytes {
  companion object {
    private val hasher =
      ThreadLocal.withInitial {
        MessageDigest.getInstance("SHA-512")
      }
  }

  override fun hash(
    input: ByteArray,
    salt: ByteArray
  ): ByteArray {
    val digest = hasher.get()
    val output = digest.digest(input)
    digest.update(salt)
    digest.update(output)
    return digest.digest()
  }
}
