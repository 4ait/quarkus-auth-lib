package ru.code4a.auth.encoding

import jakarta.enterprise.context.ApplicationScoped
import java.util.Base64

@ApplicationScoped
class EncoderBase64 {
  companion object {
    private val encoder =
      ThreadLocal.withInitial {
        Base64.getEncoder()
      }
  }

  fun encode(input: ByteArray): String = encoder.get().encodeToString(input)
}
