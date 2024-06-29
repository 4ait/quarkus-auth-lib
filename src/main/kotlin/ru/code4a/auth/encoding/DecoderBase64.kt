package ru.code4a.auth.encoding

import jakarta.enterprise.context.ApplicationScoped
import java.util.Base64

@ApplicationScoped
class DecoderBase64 {
  companion object {
    private val decoder =
      ThreadLocal.withInitial {
        Base64.getDecoder()
      }
  }

  fun decode(input: String): ByteArray = decoder.get().decode(input)
}
