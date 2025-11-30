package ru.code4a.auth.test

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
import ru.code4a.auth.SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.security.SessionCsrfTokenCreator
import ru.code4a.auth.security.SessionPublicTokenCreator
import ru.code4a.auth.security.SessionUserTokenCreator
import ru.code4a.auth.security.SessionUserTokenCreator.TokenData
import ru.code4a.errorhandling.Error
import ru.code4a.errorhandling.Ok
import java.time.Instant

class SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithmTest {
  private lateinit var sessionAuthorizer: SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm
  private lateinit var sessionUserTokenCreator: SessionUserTokenCreator
  private lateinit var sessionPublicTokenCreator: SessionPublicTokenCreator
  private lateinit var sessionCsrfTokenCreator: SessionCsrfTokenCreator
  private lateinit var base64: DecoderBase64
  private lateinit var userSessionStorageGetter: SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.UserSessionStorageGetter

  @BeforeEach
  fun setup() {
    sessionUserTokenCreator = mock(SessionUserTokenCreator::class.java)
    sessionPublicTokenCreator = mock(SessionPublicTokenCreator::class.java)
    sessionCsrfTokenCreator = mock(SessionCsrfTokenCreator::class.java)
    base64 = mock(DecoderBase64::class.java)
    userSessionStorageGetter =
      mock(SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.UserSessionStorageGetter::class.java)

    sessionAuthorizer =
      SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm(
        sessionUserTokenCreator,
        sessionPublicTokenCreator,
        sessionCsrfTokenCreator,
        base64
      )
  }

  private inline fun <reified T> any(): T = any(T::class.java)

  @Test
  fun testAuthorizeBySessionUserToken_Success() {
    val sessionUserTokenBase64 = "userToken"
    val sessionCsrfTokenBase64 = "csrfToken"
    val userSessionTokenId = 1L
    val userId = 1L
    val sessionPublicTokenBase64 = "publicToken"
    val sessionCsrfTokenSaltBase64 = "csrfSalt"
    val sessionCsrfTokenSaltByteArray = byteArrayOf(8, 9, 0)
    val authorizedAt = Instant.now().minusSeconds(3600)
    val validUntil = Instant.now().plusSeconds(3600)
    val sessionPrivateCsrfTokenBytes = byteArrayOf(4, 5, 6)

    val sessionUserTokenData =
      TokenData(
        userSessionTokenId,
        byteArrayOf(1, 2, 3),
        sessionPrivateCsrfTokenBytes
      )

    `when`(sessionUserTokenCreator.unpackBase64Token(sessionUserTokenBase64)).thenReturn(sessionUserTokenData)
    `when`(userSessionStorageGetter.getByUserSessionTokenId(userSessionTokenId)).thenReturn(
      Ok(
        SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.SessionStorageData(
          userId,
          1L,
          userSessionTokenId,
          sessionPublicTokenBase64,
          sessionCsrfTokenSaltBase64,
          authorizedAt,
          null,
          validUntil
        )
      )
    )
    `when`(
      sessionPublicTokenCreator.verifyBase64Token(
        sessionPublicTokenBase64,
        sessionUserTokenData.sessionPrivateTokenBytes
      )
    ).thenReturn(true)

    `when`(base64.decode(sessionCsrfTokenSaltBase64)).thenReturn(sessionCsrfTokenSaltByteArray)

    `when`(
      sessionCsrfTokenCreator.createBase64Token(sessionPrivateCsrfTokenBytes, sessionCsrfTokenSaltByteArray)
    ).thenReturn(sessionCsrfTokenBase64)

    val result =
      sessionAuthorizer.authorizeBySessionUserToken(
        userSessionStorageGetter,
        true,
        sessionUserTokenBase64,
        sessionCsrfTokenBase64
      )

    assertTrue(result is Ok)
    val authorizeData = (result as Ok).value
    assertEquals(userId, authorizeData.userId)
    assertEquals(userSessionTokenId, authorizeData.userSessionTokenId)
    assertEquals(sessionPublicTokenBase64, authorizeData.sessionPublicTokenBase64)
    assertEquals(sessionCsrfTokenBase64, authorizeData.sessionCsrfTokenBase64)
  }

  @Test
  fun testAuthorizeBySessionUserToken_SessionNotFound() {
    val sessionUserTokenBase64 = "userToken"
    val userSessionTokenId = 1L

    val sessionUserTokenData =
      TokenData(
        userSessionTokenId,
        byteArrayOf(1, 2, 3),
        byteArrayOf(4, 5, 6)
      )

    `when`(sessionUserTokenCreator.unpackBase64Token(sessionUserTokenBase64)).thenReturn(sessionUserTokenData)
    `when`(userSessionStorageGetter.getByUserSessionTokenId(userSessionTokenId))
      .thenReturn(Error(SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.UserSessionStorageGetter.NotFoundError()))

    val result =
      sessionAuthorizer.authorizeBySessionUserToken(
        userSessionStorageGetter,
        false,
        sessionUserTokenBase64,
        null
      )

    assertTrue(result is Error)
    assertEquals(
      SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.AuthorizeSessionError.SessionNotAuthorized,
      (result as Error).value
    )
  }

  @Test
  fun testAuthorizeBySessionUserToken_ExpiredToken() {
    val sessionUserTokenBase64 = "userToken"
    val userSessionTokenId = 1L
    val userId = 1L
    val sessionPublicTokenBase64 = "publicToken"
    val sessionCsrfTokenSaltBase64 = "csrfSalt"
    val authorizedAt = Instant.now().minusSeconds(7200)
    val validUntil = Instant.now().minusSeconds(3600)

    val sessionUserTokenData =
      TokenData(
        userSessionTokenId,
        byteArrayOf(1, 2, 3),
        byteArrayOf(4, 5, 6)
      )

    `when`(sessionUserTokenCreator.unpackBase64Token(sessionUserTokenBase64)).thenReturn(sessionUserTokenData)
    `when`(userSessionStorageGetter.getByUserSessionTokenId(userSessionTokenId)).thenReturn(
      Ok(
        SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.SessionStorageData(
          userId,
          1L,
          userSessionTokenId,
          sessionPublicTokenBase64,
          sessionCsrfTokenSaltBase64,
          authorizedAt,
          null,
          validUntil
        )
      )
    )

    val result =
      sessionAuthorizer.authorizeBySessionUserToken(
        userSessionStorageGetter,
        false,
        sessionUserTokenBase64,
        null
      )

    assertTrue(result is Error)
    assertTrue((result as Error).value is SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.AuthorizeSessionError.AccessTokenExpired)
  }

  @Test
  fun testAuthorizeBySessionUserToken_InvalidCSRFToken() {
    val sessionUserTokenBase64 = "userToken"
    val sessionCsrfTokenBase64 = "invalidCsrfToken"
    val userSessionTokenId = 1L
    val userId = 1L
    val sessionPublicTokenBase64 = "publicToken"
    val sessionCsrfTokenSaltBase64 = "csrfSalt"
    val authorizedAt = Instant.now().minusSeconds(3600)
    val validUntil = Instant.now().plusSeconds(3600)

    val sessionUserTokenData =
      TokenData(
        userSessionTokenId,
        byteArrayOf(1, 2, 3),
        byteArrayOf(4, 5, 6)
      )

    `when`(sessionUserTokenCreator.unpackBase64Token(sessionUserTokenBase64)).thenReturn(sessionUserTokenData)
    `when`(userSessionStorageGetter.getByUserSessionTokenId(userSessionTokenId)).thenReturn(
      Ok(
        SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.SessionStorageData(
          userId,
          1L,
          userSessionTokenId,
          sessionPublicTokenBase64,
          sessionCsrfTokenSaltBase64,
          authorizedAt,
          null,
          validUntil
        )
      )
    )
    `when`(
      sessionPublicTokenCreator.verifyBase64Token(
        sessionPublicTokenBase64,
        sessionUserTokenData.sessionPrivateTokenBytes
      )
    ).thenReturn(true)
    `when`(sessionCsrfTokenCreator.createBase64Token(any(), any())).thenReturn("validCsrfToken")

    val result =
      sessionAuthorizer.authorizeBySessionUserToken(
        userSessionStorageGetter,
        true,
        sessionUserTokenBase64,
        sessionCsrfTokenBase64
      )

    assertTrue(result is Error)
    assertTrue((result as Error).value is SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.AuthorizeSessionError.CSRFTokenIsNotValid)
  }
}
