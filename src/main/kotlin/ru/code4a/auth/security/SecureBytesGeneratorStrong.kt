package ru.code4a.auth.security

import jakarta.enterprise.context.ApplicationScoped
import java.security.SecureRandom

@ApplicationScoped
class SecureBytesGeneratorStrong {
  private val secureRandom =
    ThreadLocal.withInitial {
      SecureRandom.getInstanceStrong()
    }

  fun generate(lengthBytes: Int): ByteArray {
    val byteArray = ByteArray(lengthBytes)
    secureRandom.get().nextBytes(byteArray)

    return byteArray
  }
}
