package ru.code4a.auth.security

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.security.hasher.base.BaseAuthHasherBytes

@ApplicationScoped
class SessionCsrfTokenCreator(
  private val encoderBase64: EncoderBase64,
  private val baseAuthHasherBytes: BaseAuthHasherBytes
) {
  fun createBase64Token(
    privateCsrfToken: ByteArray,
    salt: ByteArray
  ): String =
    encoderBase64.encode(
      baseAuthHasherBytes.hash(
        privateCsrfToken,
        salt
      )
    )
}
