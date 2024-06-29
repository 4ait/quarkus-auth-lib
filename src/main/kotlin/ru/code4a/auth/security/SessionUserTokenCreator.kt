package ru.code4a.auth.security

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.security.ciphers.CipherSessionUserToken
import java.nio.ByteBuffer
import java.nio.ByteOrder

@ApplicationScoped
class SessionUserTokenCreator(
  private val cipherSessionUserToken: CipherSessionUserToken,
  private val encoderBase64: EncoderBase64,
  private val decoderBase64: DecoderBase64
) {
  data class TokenData(
    val userSessionTokenId: Long,
    val sessionPrivateTokenBytes: ByteArray,
    val sessionPrivateCsrfTokenBytes: ByteArray
  )

  fun createBase64Token(
    userSessionTokenId: Long,
    sessionPrivateTokenBytes: ByteArray,
    sessionPrivateCsrfTokenBytes: ByteArray
  ): String {
    val packedSessionUserPrivateToken =
      ByteBuffer
        .allocate(Long.SIZE_BYTES + sessionPrivateTokenBytes.size + sessionPrivateCsrfTokenBytes.size)
        .putLong(userSessionTokenId)
        .put(sessionPrivateTokenBytes)
        .put(sessionPrivateCsrfTokenBytes)
        .order(ByteOrder.BIG_ENDIAN)
        .array()

    val sessionUserTokenBytes = cipherSessionUserToken.encrypt(packedSessionUserPrivateToken)

    return encoderBase64.encode(sessionUserTokenBytes)
  }

  fun unpackBase64Token(token: String): TokenData {
    val encryptedBytes = decoderBase64.decode(token)

    val bytes = cipherSessionUserToken.decrypt(encryptedBytes)

    return TokenData(
      userSessionTokenId = ByteBuffer.wrap(bytes, 0, 8).order(ByteOrder.BIG_ENDIAN).getLong(),
      sessionPrivateTokenBytes = bytes.copyOfRange(8, 8 + 512 / 8),
      sessionPrivateCsrfTokenBytes = bytes.copyOfRange(8 + 512 / 8, bytes.size)
    )
  }
}
