package ru.code4a.auth.security

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.security.hasher.HasherBytesSHA512

@ApplicationScoped
class SessionCsrfTokenCreator(
  private val encoderBase64: EncoderBase64,
  private val sha512: HasherBytesSHA512
) {
  fun createBase64Token(
    privateCsrfToken: ByteArray,
    salt: ByteArray
  ): String =
    encoderBase64.encode(
      sha512.hash(
        privateCsrfToken,
        salt
      )
    )
}
