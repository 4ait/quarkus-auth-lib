package ru.code4a.auth.test

import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import org.junit.jupiter.api.Test
import ru.code4a.auth.SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm
import ru.code4a.auth.SessionRequestNewAccessTokenWithERPAuthAlgorithm
import ru.code4a.auth.UserAuthorizerByLoginPasswordWithERPAuthAlgorithm
import ru.code4a.auth.interfaces.User
import ru.code4a.auth.interfaces.UserAccessTokenWriter
import ru.code4a.auth.interfaces.UserByLoginGetter
import ru.code4a.auth.interfaces.UserSessionStorageWriter
import ru.code4a.auth.interfaces.UserSessionTokenNewIdGetter
import ru.code4a.errorhandling.Error
import ru.code4a.errorhandling.Ok
import ru.code4a.errorhandling.OkOrError
import java.time.Instant

@QuarkusTest
class AuthorizationAndValidationBase {
  @Inject
  lateinit var userAuthorizerByLoginPasswordWithERPAuthAlgorithm: UserAuthorizerByLoginPasswordWithERPAuthAlgorithm

  @Inject
  lateinit var authorizationDataUserCreator: _root_ide_package_.ru.code4a.auth.AuthorizationDataUserCreator

  @Inject
  lateinit var sessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm: SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm

  @Inject
  lateinit var sessionRequestNewAccessTokenWithERPAuthAlgorithm: SessionRequestNewAccessTokenWithERPAuthAlgorithm

  @Test
  fun failedSessionAuthorizationBySessionUserToken() {
    val userId = 1L
    val userLogin = "ya user"
    val userPassword = "asdfwef34cf"
    val userSessionId = 1L

    val userAuthorizationData = authorizationDataUserCreator.compute(userPassword)

    val userByLoginGetter =
      object : UserByLoginGetter {
        override fun get(login: String): OkOrError<User, UserByLoginGetter.NotFoundError> =
          Ok(
            object : User {
              override val id: Long
                get() = userId
              override val authorizationHashBase64: String
                get() = userAuthorizationData.userAuthorizationHashBase64
              override val authorizationSaltBase64: String
                get() = userAuthorizationData.authorizationSaltBase64
            }
          )
      }

    val userSessionTokenNewIdGetter =
      object : UserSessionTokenNewIdGetter {
        var curSessionTokenId = 1L

        override fun <T> with(block: (userSessionTokenId: Long) -> T): T {
          val next = curSessionTokenId

          curSessionTokenId += 1

          return block(next)
        }
      }

    var createdPublicTokenSets: String? = null
    var authorizedAtSets: Instant? = null
    var validUntilSets: Instant? = null
    var sessionCsrfTokenSaltBase64Sets: String? = null

    val userSessionStorageWriter =
      object : UserSessionStorageWriter {
        override fun write(
          userId: Long,
          userSessionTokenId: Long,
          sessionPublicTokenBase64: String,
          sessionCsrfTokenSaltBase64: String,
          authorizedAt: Instant,
          validUntil: Instant
        ): OkOrError<Unit, Unit> {
          createdPublicTokenSets = sessionPublicTokenBase64
          authorizedAtSets = authorizedAt
          validUntilSets = validUntil
          sessionCsrfTokenSaltBase64Sets = sessionCsrfTokenSaltBase64

          return Ok(Unit)
        }
      }

    val authorizationDataRaw =
      userAuthorizerByLoginPasswordWithERPAuthAlgorithm.authorizeUserByLoginPassword(
        userByLoginGetter = userByLoginGetter,
        userSessionTokenNewIdGetter = userSessionTokenNewIdGetter,
        userSessionStorageWriter = userSessionStorageWriter,
        login = userLogin,
        password = userPassword
      )

    val authorizationDataNotAuthorized =
      userAuthorizerByLoginPasswordWithERPAuthAlgorithm.authorizeUserByLoginPassword(
        userByLoginGetter = userByLoginGetter,
        userSessionTokenNewIdGetter = userSessionTokenNewIdGetter,
        userSessionStorageWriter = userSessionStorageWriter,
        login = userLogin,
        password = userPassword + "q"
      )

    when (authorizationDataNotAuthorized) {
      is Error -> {}
      is Ok -> throw Exception("User should not authorized")
    }

    val createdWithPublicToken =
      if (createdPublicTokenSets != null) {
        createdPublicTokenSets!!
      } else {
        throw Exception("publicTokenSets should not be null")
      }

    val sessionCsrfTokenSaltBase64 =
      if (sessionCsrfTokenSaltBase64Sets != null) {
        sessionCsrfTokenSaltBase64Sets!!
      } else {
        throw Exception("sessionCsrfTokenSaltBase64Sets should not be null")
      }

    val createdWithAuthorizedAt =
      if (authorizedAtSets != null) {
        authorizedAtSets!!
      } else {
        throw Exception("authorizedAtSets should not be null")
      }

    val createdWithValidUntil =
      if (validUntilSets != null) {
        validUntilSets!!
      } else {
        throw Exception("validUntilSets should not be null")
      }

    val authorizationData =
      when (authorizationDataRaw) {
        is Error -> throw Exception("Invalid authorization data")
        is Ok -> authorizationDataRaw.value
      }

    val userSessionStorageGetter =
      object : SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.UserSessionStorageGetter {
        override fun getByUserSessionTokenId(
          userSessionTokenId: Long
        ): OkOrError<SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.SessionStorageData, SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.UserSessionStorageGetter.NotFoundError> =
          Ok(
            SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.SessionStorageData(
              userId = userId,
              sessionPublicTokenBase64 = createdWithPublicToken,
              authorizedAt = createdWithAuthorizedAt,
              validUntil = createdWithValidUntil,
              sessionCsrfTokenSaltBase64 = sessionCsrfTokenSaltBase64,
              unauthorizedAt = null,
              userSessionId = userSessionId,
              userSessionTokenId = userSessionTokenId
            )
          )
      }

    val authorizeSessionData =
      sessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.authorizeBySessionUserToken(
        userSessionStorageGetter = userSessionStorageGetter,
        verifyCsrfToken = false,
        sessionUserTokenBase64 = authorizationData.sessionUserTokenBase64,
        sessionCsrfTokenBase64 = null
      )

    when (authorizeSessionData) {
      is Error -> throw Exception("User should be authorized")
      is Ok -> {}
    }

    val authorizeSessionDataCsrf =
      sessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.authorizeBySessionUserToken(
        userSessionStorageGetter = userSessionStorageGetter,
        verifyCsrfToken = true,
        sessionUserTokenBase64 = authorizationData.sessionUserTokenBase64,
        sessionCsrfTokenBase64 = authorizationData.sessionCsrfTokenBase64
      )

    when (authorizeSessionDataCsrf) {
      is Error -> throw Exception("User should be authorized")
      is Ok -> {}
    }

    val authorizeSessionDataCsrfNotValidSessionUserToken =
      sessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.authorizeBySessionUserToken(
        userSessionStorageGetter = userSessionStorageGetter,
        verifyCsrfToken = true,
        sessionUserTokenBase64 = authorizationData.sessionUserTokenBase64 + "2342",
        sessionCsrfTokenBase64 = authorizationData.sessionCsrfTokenBase64
      )

    when (authorizeSessionDataCsrfNotValidSessionUserToken) {
      is Error -> {}
      is Ok -> throw Exception("User should not be authorized")
    }

    val authorizeSessionDataCsrfNotValidSessionUserTokenBase64 =
      sessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.authorizeBySessionUserToken(
        userSessionStorageGetter = userSessionStorageGetter,
        verifyCsrfToken = true,
        sessionUserTokenBase64 = "nOB4hckm5T4aL4Vg4S2IQctXU2gTup41ez6IH6SkER94bh09mNbmKzO/fS6eTLlwia3l5qr0mOP3pITjTBGLSaij+8jgg3xbtPW9F2O0dMpvAdSG7hpDJQcX61PfGu5j",
        sessionCsrfTokenBase64 = authorizationData.sessionCsrfTokenBase64
      )

    when (authorizeSessionDataCsrfNotValidSessionUserTokenBase64) {
      is Error -> {}
      is Ok -> throw Exception("User should not be authorized")
    }

    val authorizeSessionDataCsrfNotValidSessionCsrfTokenBase64Base64 =
      sessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.authorizeBySessionUserToken(
        userSessionStorageGetter = userSessionStorageGetter,
        verifyCsrfToken = true,
        sessionUserTokenBase64 = authorizationData.sessionUserTokenBase64,
        sessionCsrfTokenBase64 = "nOB4hckm5T4aL4Vg4S2IQctXU2gTup41ez6IH6SkER94bh09mNbmKzO/fS6eTLlwia3l5qr0mOP3pITjTBGLSaij+8jgg3xbtPW9F2O0dMpvAdSG7hpDJQcX61PfGu5j"
      )

    when (authorizeSessionDataCsrfNotValidSessionCsrfTokenBase64Base64) {
      is Error -> {}
      is Ok -> throw Exception("User should not be authorized")
    }

    var newCreatedPublicTokenSets: String? = null
    var newSessionIdSets: Long? = null
    var newUserSessionTokenIdSets: Long? = null

    val userAccessTokenWriter =
      object : UserAccessTokenWriter {
        override fun write(
          userSessionId: Long,
          userSessionTokenId: Long,
          sessionPublicTokenBase64: String,
          validUntil: Instant
        ) {
          newSessionIdSets = userSessionId
          newUserSessionTokenIdSets = userSessionTokenId
          newCreatedPublicTokenSets = sessionPublicTokenBase64
        }
      }

    val newAccessTokenData =
      sessionRequestNewAccessTokenWithERPAuthAlgorithm.requestNewUserAccessToken(
        userAccessTokenWriter = userAccessTokenWriter,
        userSessionTokenNewIdGetter = userSessionTokenNewIdGetter,
        userSessionId = userSessionId,
        sessionUserTokenBase64 = authorizationDataRaw.value.sessionUserTokenBase64
      )

    assert(newSessionIdSets == userSessionId)

    val newCreatedWithPublicToken =
      if (newCreatedPublicTokenSets != null) {
        newCreatedPublicTokenSets!!
      } else {
        throw Exception("newCreatedPublicTokenSets should not be null")
      }

    val newUserSessionTokenId =
      if (newUserSessionTokenIdSets != null) {
        newUserSessionTokenIdSets!!
      } else {
        throw Exception("newUserSessionTokenIdSets should not be null")
      }

    val newUserSessionStorageGetter =
      object : SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.UserSessionStorageGetter {
        override fun getByUserSessionTokenId(
          userSessionTokenId: Long
        ): OkOrError<SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.SessionStorageData, SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.UserSessionStorageGetter.NotFoundError> =
          Ok(
            SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.SessionStorageData(
              userId = userId,
              sessionPublicTokenBase64 = newCreatedWithPublicToken,
              authorizedAt = createdWithAuthorizedAt,
              validUntil = createdWithValidUntil,
              sessionCsrfTokenSaltBase64 = sessionCsrfTokenSaltBase64,
              unauthorizedAt = null,
              userSessionId = userSessionId,
              userSessionTokenId = newUserSessionTokenId
            )
          )
      }

    val authorizeSessionDataWithNewToken =
      sessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.authorizeBySessionUserToken(
        userSessionStorageGetter = newUserSessionStorageGetter,
        verifyCsrfToken = true,
        sessionUserTokenBase64 = newAccessTokenData.sessionUserTokenBase64,
        sessionCsrfTokenBase64 = authorizationData.sessionCsrfTokenBase64
      )

    when (authorizeSessionDataWithNewToken) {
      is Error -> throw Exception("User should be authorized")
      is Ok -> {}
    }

    val newUserSessionStorageGetterWithUnauthorizedAt =
      object : SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.UserSessionStorageGetter {
        override fun getByUserSessionTokenId(
          userSessionTokenId: Long
        ): OkOrError<SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.SessionStorageData, SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.UserSessionStorageGetter.NotFoundError> =
          Ok(
            SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.SessionStorageData(
              userId = userId,
              sessionPublicTokenBase64 = newCreatedWithPublicToken,
              authorizedAt = createdWithAuthorizedAt,
              validUntil = createdWithValidUntil,
              sessionCsrfTokenSaltBase64 = sessionCsrfTokenSaltBase64,
              unauthorizedAt = Instant.now(),
              userSessionId = userSessionId,
              userSessionTokenId = newUserSessionTokenId
            )
          )
      }

    val authorizeSessionDataWithNewTokenAndUnauthorizedAt =
      sessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.authorizeBySessionUserToken(
        userSessionStorageGetter = newUserSessionStorageGetterWithUnauthorizedAt,
        verifyCsrfToken = true,
        sessionUserTokenBase64 = newAccessTokenData.sessionUserTokenBase64,
        sessionCsrfTokenBase64 = authorizationData.sessionCsrfTokenBase64
      )

    when (authorizeSessionDataWithNewTokenAndUnauthorizedAt) {
      is Error -> {}
      is Ok -> throw Exception("User should not be authorized")
    }
  }
}
