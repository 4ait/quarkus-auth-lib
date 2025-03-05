package ru.code4a.auth.encoding

import jakarta.enterprise.context.ApplicationScoped
import java.util.Base64

@ApplicationScoped
class EncoderBase64 {
  fun encode(input: ByteArray): String = Base64.getEncoder().encodeToString(input)
}
