package ru.code4a.auth

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.interfaces.SessionPublicTokenGeneratorResult
import ru.code4a.auth.interfaces.UserSessionStorageWriter
import ru.code4a.auth.interfaces.UserSessionTokenNewIdGetter
import ru.code4a.auth.security.SecureBytesGeneratorStrong
import ru.code4a.auth.security.SessionCsrfTokenCreator
import ru.code4a.auth.security.SessionPublicTokenCreator
import ru.code4a.auth.security.SessionUserTokenCreator
import java.time.Instant

@ApplicationScoped
class SessionCreatorWithERPAuthAlgorithm(
  private val secureBytesGenerator: SecureBytesGeneratorStrong,
  private val sessionUserTokenCreator: SessionUserTokenCreator,
  private val sessionCsrfTokenCreator: SessionCsrfTokenCreator,
  private val sessionPublicTokenCreator: SessionPublicTokenCreator,
  private val base64: EncoderBase64
) {
  fun createSession(
    userSessionTokenNewIdGetter: UserSessionTokenNewIdGetter,
    userSessionStorageWriter: UserSessionStorageWriter,
    userId: Long,
    authorizedAt: Instant,
    validUntil: Instant
  ): SessionPublicTokenGeneratorResult {
    return userSessionTokenNewIdGetter.with { userSessionTokenId ->
      val sessionPrivateTokenBytes = secureBytesGenerator.generate(512 / 8)
      val sessionPrivateCsrfTokenBytes = secureBytesGenerator.generate(256 / 8)

      val sessionPublicTokenBase64 = sessionPublicTokenCreator.createBase64Token(sessionPrivateTokenBytes)

      val sessionUserTokenBase64 =
        sessionUserTokenCreator.createBase64Token(
          userSessionTokenId = userSessionTokenId,
          sessionPrivateTokenBytes = sessionPrivateTokenBytes,
          sessionPrivateCsrfTokenBytes = sessionPrivateCsrfTokenBytes
        )

      val sessionCsrfTokenSaltBytes = secureBytesGenerator.generate(256 / 8)

      val sessionCsrfTokenBase64 =
        sessionCsrfTokenCreator.createBase64Token(
          sessionPrivateCsrfTokenBytes,
          sessionCsrfTokenSaltBytes
        )

      val sessionCsrfTokenSaltBase64 = base64.encode(sessionCsrfTokenSaltBytes)

      val writeResult =
        userSessionStorageWriter.write(
          userId = userId,
          userSessionTokenId = userSessionTokenId,
          sessionPublicTokenBase64 = sessionPublicTokenBase64,
          sessionCsrfTokenSaltBase64 = sessionCsrfTokenSaltBase64,
          authorizedAt = authorizedAt,
          validUntil = validUntil
        )

      if (writeResult.isError) {
        throw Exception("Cannot write session token. Should not happen by design")
      }

      return@with object : SessionPublicTokenGeneratorResult {
        override fun getUserSessionTokenId(): Long = userSessionTokenId

        override fun getSessionPublicTokenBase64(): String = sessionPublicTokenBase64

        override fun getSessionUserTokenBase64(): String = sessionUserTokenBase64

        override fun getCsrfTokenBase64(): String = sessionCsrfTokenBase64

        override fun getValidUntil(): Instant = validUntil
      }
    }
  }
}
