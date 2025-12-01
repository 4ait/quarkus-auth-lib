package ru.code4a.auth.test

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.any
import org.mockito.Mockito.eq
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import ru.code4a.auth.SessionCreatorWithERPAuthAlgorithm
import ru.code4a.auth.UserAuthorizerByLoginPasswordWithERPAuthAlgorithm
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.interfaces.SessionPublicTokenGeneratorResult
import ru.code4a.auth.interfaces.UserByLoginGetter
import ru.code4a.auth.interfaces.UserSessionStorageWriter
import ru.code4a.auth.interfaces.UserSessionTokenNewIdGetter
import ru.code4a.auth.security.UserAuthorizationHashComputer
import ru.code4a.auth.structures.UserData
import ru.code4a.errorhandling.Ok
import java.time.Instant

class UserAuthorizerByLoginPasswordWithERPAuthAlgorithmTest {
  private lateinit var userAuthorizer: UserAuthorizerByLoginPasswordWithERPAuthAlgorithm
  private lateinit var decoderBase64: DecoderBase64
  private lateinit var userAuthorizationHashComputer: UserAuthorizationHashComputer
  private lateinit var sessionCreator: SessionCreatorWithERPAuthAlgorithm
  private lateinit var userByLoginGetter: UserByLoginGetter
  private lateinit var userSessionTokenNewIdGetter: UserSessionTokenNewIdGetter
  private lateinit var userSessionStorageWriter: UserSessionStorageWriter

  @BeforeEach
  fun setup() {
    decoderBase64 = mock(DecoderBase64::class.java)
    userAuthorizationHashComputer = mock(UserAuthorizationHashComputer::class.java)
    sessionCreator = mock(SessionCreatorWithERPAuthAlgorithm::class.java)
    userByLoginGetter = mock(UserByLoginGetter::class.java)
    userSessionTokenNewIdGetter = mock(UserSessionTokenNewIdGetter::class.java)
    userSessionStorageWriter = mock(UserSessionStorageWriter::class.java)

    userAuthorizer =
      UserAuthorizerByLoginPasswordWithERPAuthAlgorithm(
        decoderBase64,
        userAuthorizationHashComputer,
        sessionCreator
      )
  }

  private inline fun <reified T> any(): T = any(T::class.java)

  @Test
  fun testAuthorizeUserByLoginPassword_Success() {
    val login = "testuser"
    val password = "password123"
    val userId = 1L
    val saltBase64 = "salt"
    val hashBase64 = "hash"
    val salt = byteArrayOf(1, 2, 3)

    `when`(userByLoginGetter.get(login)).thenReturn(Ok(UserData(userId, hashBase64, saltBase64)))
    `when`(decoderBase64.decode(saltBase64)).thenReturn(salt)
    `when`(
      userAuthorizationHashComputer.verifyHashBase64(
        expectedHashBase64 = hashBase64,
        password = password,
        authorizationSalt = salt
      )
    ).thenReturn(true)

    `when`(sessionCreator.createSession(any(), any(), eq(userId), any(), any())).thenReturn(
      object : SessionPublicTokenGeneratorResult {
        override fun getUserSessionTokenId(): Long = 1L

        override fun getSessionPublicTokenBase64(): String = "publicToken"

        override fun getSessionUserTokenBase64(): String = "userToken"

        override fun getCsrfTokenBase64(): String = "csrfToken"

        override fun getValidUntil(): Instant = Instant.now().plusSeconds(3600)
      }
    )

    val result =
      userAuthorizer.authorizeUserByLoginPassword(
        userByLoginGetter,
        userSessionTokenNewIdGetter,
        userSessionStorageWriter,
        login,
        password
      )

    assertTrue(result is Ok)
    val authorizeData = (result as Ok).value
    assertEquals(userId, authorizeData.userId)
    assertEquals("userToken", authorizeData.sessionUserTokenBase64)
    assertEquals("csrfToken", authorizeData.sessionCsrfTokenBase64)
  }

  @Test
  fun testAuthorizeUserByLoginPassword_UserNotFound() {
    val login = "nonexistent"
    val password = "password123"

    `when`(userByLoginGetter.get(login)).thenReturn(ru.code4a.errorhandling.Error(UserByLoginGetter.NotFoundError()))

    val result =
      userAuthorizer.authorizeUserByLoginPassword(
        userByLoginGetter,
        userSessionTokenNewIdGetter,
        userSessionStorageWriter,
        login,
        password
      )

    assertTrue(result is ru.code4a.errorhandling.Error)
    assertEquals(
      UserAuthorizerByLoginPasswordWithERPAuthAlgorithm.AuthorizeUserError.UserNotAuthorized,
      (result as ru.code4a.errorhandling.Error).value
    )
  }

  @Test
  fun testAuthorizeUserByLoginPassword_InvalidPassword() {
    val login = "testuser"
    val password = "wrongpassword"
    val userId = 1L
    val saltBase64 = "salt"
    val hashBase64 = "hash"
    val salt = byteArrayOf(1, 2, 3)

    `when`(userByLoginGetter.get(login)).thenReturn(Ok(UserData(userId, hashBase64, saltBase64)))
    `when`(decoderBase64.decode(saltBase64)).thenReturn(salt)
    `when`(
      userAuthorizationHashComputer.verifyHashBase64(
        expectedHashBase64 = hashBase64,
        password = password,
        authorizationSalt = salt
      )
    ).thenReturn(false)

    val result =
      userAuthorizer.authorizeUserByLoginPassword(
        userByLoginGetter,
        userSessionTokenNewIdGetter,
        userSessionStorageWriter,
        login,
        password
      )

    assertTrue(result is ru.code4a.errorhandling.Error)
    assertEquals(
      UserAuthorizerByLoginPasswordWithERPAuthAlgorithm.AuthorizeUserError.UserNotAuthorized,
      (result as ru.code4a.errorhandling.Error).value
    )
  }
}
