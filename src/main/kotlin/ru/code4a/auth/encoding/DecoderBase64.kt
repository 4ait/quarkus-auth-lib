package ru.code4a.auth.encoding

import jakarta.enterprise.context.ApplicationScoped
import java.util.Base64

@ApplicationScoped
class DecoderBase64 {
  fun decode(input: String): ByteArray = Base64.getDecoder().decode(input)
}
