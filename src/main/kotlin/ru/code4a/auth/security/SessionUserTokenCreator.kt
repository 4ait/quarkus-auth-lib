package ru.code4a.auth.security

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.security.ciphers.PrefixedCipherSelector
import java.nio.ByteBuffer
import java.nio.ByteOrder

@ApplicationScoped
class SessionUserTokenCreator(
  private val prefixedCipherSelector: PrefixedCipherSelector
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

    return prefixedCipherSelector.encryptWithPossiblePrefix(packedSessionUserPrivateToken)
  }

  fun unpackBase64Token(token: String): TokenData {
    val bytes = prefixedCipherSelector.decryptWithPossiblePrefix(token)

    return TokenData(
      userSessionTokenId = ByteBuffer.wrap(bytes, 0, 8).order(ByteOrder.BIG_ENDIAN).getLong(),
      sessionPrivateTokenBytes = bytes.copyOfRange(8, 8 + 512 / 8),
      sessionPrivateCsrfTokenBytes = bytes.copyOfRange(8 + 512 / 8, bytes.size)
    )
  }
}
