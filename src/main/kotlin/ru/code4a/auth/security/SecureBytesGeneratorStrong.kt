package ru.code4a.auth.security

import jakarta.enterprise.context.ApplicationScoped
import java.security.SecureRandom

@ApplicationScoped
class SecureBytesGeneratorStrong {
  private val secureRandom = SecureRandom.getInstanceStrong()

  fun generate(lengthBytes: Int): ByteArray {
    val byteArray = ByteArray(lengthBytes)
    secureRandom.nextBytes(byteArray)

    return byteArray
  }
}
