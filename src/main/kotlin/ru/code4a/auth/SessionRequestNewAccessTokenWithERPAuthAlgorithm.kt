package ru.code4a.auth

import jakarta.annotation.PostConstruct
import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.inject.ConfigProperty
import ru.code4a.auth.interfaces.UserAccessTokenWriter
import ru.code4a.auth.interfaces.UserSessionTokenNewIdGetter
import ru.code4a.auth.security.SecureBytesGeneratorStrong
import ru.code4a.auth.security.SessionPublicTokenCreator
import ru.code4a.auth.security.SessionUserTokenCreator
import java.time.Duration
import java.time.Instant

@ApplicationScoped
class SessionRequestNewAccessTokenWithERPAuthAlgorithm(
  private val sessionUserTokenCreator: SessionUserTokenCreator,
  private val secureBytesGeneratorStrong: SecureBytesGeneratorStrong,
  private val sessionPublicTokenCreator: SessionPublicTokenCreator
) {
  data class NewAccessTokenData(
    val sessionUserTokenBase64: String,
    val userSessionTokenId: Long,
    val validUntil: Instant
  )

  @ConfigProperty(name = "foura.fauth.minutes-token-valid")
  private lateinit var minutesTokenValidRaw: String

  private var minutesTokenValid: Long = 0

  @PostConstruct
  protected fun init() {
    minutesTokenValid = minutesTokenValidRaw.toLong()
  }

  /**
   * Создает новый access токен сессии на основе текущей сессии.
   *
   * Данные сессии должны быть валидны для выполнения этой операции
   */
  fun requestNewUserAccessToken(
    userSessionTokenNewIdGetter: UserSessionTokenNewIdGetter,
    userAccessTokenWriter: UserAccessTokenWriter,
    userSessionId: Long,
    sessionUserTokenBase64: String,
    overrideValidPeriod: Duration? = null,
  ): NewAccessTokenData {
    val sessionUserTokenData = sessionUserTokenCreator.unpackBase64Token(sessionUserTokenBase64)

    val newSessionPrivateTokenBytes = secureBytesGeneratorStrong.generate(512 / 8)

    return userSessionTokenNewIdGetter.with { newUserSessionTokenId ->
      val newSessionUserTokenBase64 =
        sessionUserTokenCreator.createBase64Token(
          userSessionTokenId = newUserSessionTokenId,
          sessionPrivateTokenBytes = newSessionPrivateTokenBytes,
          sessionPrivateCsrfTokenBytes = sessionUserTokenData.sessionPrivateCsrfTokenBytes
        )

      val newSessionPublicTokenBase64 =
        sessionPublicTokenCreator.createBase64Token(newSessionPrivateTokenBytes)

      val newValidUntil = Instant.now() + (overrideValidPeriod ?: Duration.ofMinutes(minutesTokenValid))

      userAccessTokenWriter.write(
        userSessionId = userSessionId,
        userSessionTokenId = newUserSessionTokenId,
        sessionPublicTokenBase64 = newSessionPublicTokenBase64,
        validUntil = newValidUntil
      )

      return@with NewAccessTokenData(
        sessionUserTokenBase64 = newSessionUserTokenBase64,
        validUntil = newValidUntil,
        userSessionTokenId = newUserSessionTokenId
      )
    }
  }
}
