package ru.code4a.auth.security

import jakarta.enterprise.context.ApplicationScoped
import java.security.SecureRandom

@ApplicationScoped
class SecureBytesGeneratorStrong {
  fun generate(lengthBytes: Int): ByteArray {
    val secureRandom = SecureRandom.getInstanceStrong()

    val byteArray = ByteArray(lengthBytes)
    secureRandom.nextBytes(byteArray)

    return byteArray
  }
}
