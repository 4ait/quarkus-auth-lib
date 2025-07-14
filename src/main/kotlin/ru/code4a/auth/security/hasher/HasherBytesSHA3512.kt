package ru.code4a.auth.security.hasher

import jakarta.enterprise.context.ApplicationScoped
import java.security.MessageDigest

@ApplicationScoped
class HasherBytesSHA3512 : HasherBytes {
  override fun hash(
    input: ByteArray,
    salt: ByteArray
  ): ByteArray {
    val digest = MessageDigest.getInstance("SHA3-512")
    val output = digest.digest(input)
    digest.update(salt)
    digest.update(output)
    return digest.digest()
  }
}
