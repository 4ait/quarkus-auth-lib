package ru.code4a.auth

import io.quarkus.logging.Log
import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.security.SessionCsrfTokenCreator
import ru.code4a.auth.security.SessionPublicTokenCreator
import ru.code4a.auth.security.SessionUserTokenCreator
import ru.code4a.errorhandling.Error
import ru.code4a.errorhandling.Ok
import ru.code4a.errorhandling.OkOrError
import java.time.Instant

@ApplicationScoped
class SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm(
  private val sessionUserTokenCreator: SessionUserTokenCreator,
  private val sessionPublicTokenCreator: SessionPublicTokenCreator,
  private val sessionCsrfTokenCreator: SessionCsrfTokenCreator,
  private val base64: DecoderBase64
) {
  sealed interface AuthorizeSessionError {
    data object SessionNotAuthorized : AuthorizeSessionError

    data class AccessTokenExpired(
      val userSessionTokenId: Long
    ) : AuthorizeSessionError

    data class CSRFTokenIsNotFound(
      val userSessionTokenId: Long
    ) : AuthorizeSessionError

    data class CSRFTokenIsNotValid(
      val userSessionTokenId: Long
    ) : AuthorizeSessionError
  }

  interface UserSessionStorageGetter {
    class NotFoundError

    fun getByUserSessionTokenId(userSessionTokenId: Long): OkOrError<SessionStorageData, NotFoundError>
  }

  data class SessionStorageData(
    val userId: Long,
    val userSessionId: Long,
    val userSessionTokenId: Long,
    val sessionPublicTokenBase64: String,
    val sessionCsrfTokenSaltBase64: String,
    val authorizedAt: Instant,
    val unauthorizedAt: Instant?,
    val validUntil: Instant
  )

  interface AuthorizeData {
    val userId: Long
    val userSessionId: Long
    val userSessionTokenId: Long
    val sessionPublicTokenBase64: String
    val sessionCsrfTokenBase64: String
    val authorizedAt: Instant
    val unauthorizedAt: Instant?
    val validUntil: Instant
  }

  fun authorizeBySessionUserToken(
    userSessionStorageGetter: UserSessionStorageGetter,
    verifyCsrfToken: Boolean,
    sessionUserTokenBase64: String,
    sessionCsrfTokenBase64: String?
  ): OkOrError<AuthorizeData, AuthorizeSessionError> {
    try {
      val sessionUserTokenData = sessionUserTokenCreator.unpackBase64Token(sessionUserTokenBase64)

      val userSessionStorageData =
        userSessionStorageGetter.getByUserSessionTokenId(sessionUserTokenData.userSessionTokenId)

      when (userSessionStorageData) {
        is Error -> return Error(AuthorizeSessionError.SessionNotAuthorized)
        is Ok -> {
          val currentDatetime = Instant.now()

          if (userSessionStorageData.value.unauthorizedAt != null) {
            return Error(AuthorizeSessionError.SessionNotAuthorized)
          }

          if (currentDatetime.epochSecond - userSessionStorageData.value.validUntil.epochSecond > 0) {
            return Error(
              AuthorizeSessionError.AccessTokenExpired(
                userSessionTokenId = userSessionStorageData.value.userSessionTokenId
              )
            )
          }

          val sessionPublicTokenBase64 =
            sessionPublicTokenCreator.createBase64Token(sessionUserTokenData.sessionPrivateTokenBytes)

          if (userSessionStorageData.value.sessionPublicTokenBase64 != sessionPublicTokenBase64) {
            return Error(AuthorizeSessionError.SessionNotAuthorized)
          }

          val authorizeData =
            object : AuthorizeData {
              private val lazySessionCsrfTokenBase64 by lazy {
                sessionCsrfTokenCreator.createBase64Token(
                  privateCsrfToken = sessionUserTokenData.sessionPrivateCsrfTokenBytes,
                  salt = base64.decode(userSessionStorageData.value.sessionCsrfTokenSaltBase64)
                )
              }

              override val userId: Long
                get() = userSessionStorageData.value.userId
              override val userSessionId: Long
                get() = userSessionStorageData.value.userSessionId
              override val userSessionTokenId: Long
                get() = userSessionStorageData.value.userSessionTokenId
              override val sessionPublicTokenBase64: String
                get() = userSessionStorageData.value.sessionPublicTokenBase64
              override val sessionCsrfTokenBase64: String
                get() = lazySessionCsrfTokenBase64
              override val authorizedAt: Instant
                get() = userSessionStorageData.value.authorizedAt
              override val unauthorizedAt: Instant?
                get() = userSessionStorageData.value.unauthorizedAt
              override val validUntil: Instant
                get() = userSessionStorageData.value.validUntil
            }

          if (verifyCsrfToken) {
            if (sessionCsrfTokenBase64 == null) {
              return Error(AuthorizeSessionError.CSRFTokenIsNotFound(userSessionStorageData.value.userSessionTokenId))
            } else {
              if (sessionCsrfTokenBase64 != authorizeData.sessionCsrfTokenBase64) {
                return Error(AuthorizeSessionError.CSRFTokenIsNotValid(userSessionStorageData.value.userSessionTokenId))
              }
            }
          }

          return Ok(authorizeData)
        }
      }
    } catch (e: IllegalArgumentException) {
      Log.warn("Got exception on session authorize", e)

      return Error(AuthorizeSessionError.SessionNotAuthorized)
    } catch (e: javax.crypto.AEADBadTagException) {
      Log.warn("Got exception on session authorize", e)

      return Error(AuthorizeSessionError.SessionNotAuthorized)
    }
  }
}
