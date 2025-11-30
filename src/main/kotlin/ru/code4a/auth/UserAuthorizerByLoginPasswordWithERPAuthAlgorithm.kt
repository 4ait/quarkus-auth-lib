package ru.code4a.auth

import io.quarkus.logging.Log
import jakarta.annotation.PostConstruct
import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.inject.ConfigProperty
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.interfaces.UserByLoginGetter
import ru.code4a.auth.interfaces.UserSessionStorageWriter
import ru.code4a.auth.interfaces.UserSessionTokenNewIdGetter
import ru.code4a.auth.security.UserAuthorizationHashComputer
import ru.code4a.auth.structures.AuthorizeData
import ru.code4a.errorhandling.Error
import ru.code4a.errorhandling.Ok
import ru.code4a.errorhandling.OkOrError
import ru.code4a.errorhandling.asOk
import java.lang.IllegalArgumentException
import java.time.Duration
import java.time.Instant

@ApplicationScoped
class UserAuthorizerByLoginPasswordWithERPAuthAlgorithm(
  private val decoderBase64: DecoderBase64,
  private val userAuthorizationHashComputer: UserAuthorizationHashComputer,
  private val sessionCreatorWithERPAuthAlgorithm: SessionCreatorWithERPAuthAlgorithm
) {
  sealed interface AuthorizeUserError {
    data object UserNotAuthorized : AuthorizeUserError
  }

  @ConfigProperty(name = "foura.fauth.minutes-token-valid")
  private lateinit var minutesTokenValidRaw: String

  private var minutesTokenValid: Long = 0

  @PostConstruct
  protected fun init() {
    minutesTokenValid = minutesTokenValidRaw.toLong()
  }

  /**
   * Авторизует пользователя и возвращает данные о сессии
   */
  fun authorizeUserByLoginPassword(
    userByLoginGetter: UserByLoginGetter,
    userSessionTokenNewIdGetter: UserSessionTokenNewIdGetter,
    userSessionStorageWriter: UserSessionStorageWriter,
    login: String,
    password: String,
    overrideValidPeriod: Duration? = null,
  ): OkOrError<AuthorizeData, AuthorizeUserError> {
    try {
      val userResult = userByLoginGetter.get(login)

      val user =
        when (userResult) {
          is Error -> return Error(AuthorizeUserError.UserNotAuthorized)
          is Ok -> userResult.value
        }

      val authorizationSalt = decoderBase64.decode(user.authorizationSaltBase64)

      val isHashValid =
        userAuthorizationHashComputer.verifyHashBase64(
          expectedHashBase64 = user.authorizationHashBase64,
          password = password.toByteArray(),
          authorizationSalt = authorizationSalt
        )

      if (!isHashValid) {
        return Error(AuthorizeUserError.UserNotAuthorized)
      }

      val authorizedAt = Instant.now()

      val sessionData =
        sessionCreatorWithERPAuthAlgorithm.createSession(
          userId = userResult.value.id,
          userSessionTokenNewIdGetter = userSessionTokenNewIdGetter,
          userSessionStorageWriter = userSessionStorageWriter,
          authorizedAt = authorizedAt,
          validUntil = authorizedAt + (overrideValidPeriod ?: Duration.ofMinutes(minutesTokenValid))
        )

      return asOk(
        AuthorizeData(
          userId = user.id,
          sessionUserTokenBase64 = sessionData.getSessionUserTokenBase64(),
          sessionCsrfTokenBase64 = sessionData.getCsrfTokenBase64(),
          validUntil = sessionData.getValidUntil()
        )
      )
    } catch (e: IllegalArgumentException) {
      Log.warn("Got exception on authorize user login", e)

      return Error(AuthorizeUserError.UserNotAuthorized)
    } catch (e: javax.crypto.AEADBadTagException) {
      Log.warn("Got exception on authorize user login", e)

      return Error(AuthorizeUserError.UserNotAuthorized)
    }
  }
}
