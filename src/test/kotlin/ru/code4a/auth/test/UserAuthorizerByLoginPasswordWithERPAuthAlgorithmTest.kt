package ru.code4a.auth.test

import io.quarkus.test.InjectMock
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
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

@QuarkusTest
class UserAuthorizerByLoginPasswordWithERPAuthAlgorithmTest {
  @Inject
  private lateinit var userAuthorizer: UserAuthorizerByLoginPasswordWithERPAuthAlgorithm

  @InjectMock
  private lateinit var decoderBase64: DecoderBase64

  @InjectMock
  private lateinit var userAuthorizationHashComputer: UserAuthorizationHashComputer

  @InjectMock
  private lateinit var sessionCreator: SessionCreatorWithERPAuthAlgorithm

  @InjectMock
  private lateinit var userByLoginGetter: UserByLoginGetter

  @InjectMock
  private lateinit var userSessionTokenNewIdGetter: UserSessionTokenNewIdGetter

  @InjectMock
  private lateinit var userSessionStorageWriter: UserSessionStorageWriter

  @Test
  fun testAuthorizeUserByLoginPassword_Success() {
    val login = "testuser"
    val password = "password123"
    val userId = 1L
    val saltBase64 = "salt"
    val hashBase64 = "hash"
    val salt = byteArrayOf(1, 2, 3)
    val hash = byteArrayOf(4, 5, 6)
    val computedHash = byteArrayOf(4, 5, 6)

    `when`(userByLoginGetter.get(login)).thenReturn(Ok(UserData(userId, saltBase64, hashBase64)))
    `when`(decoderBase64.decode(saltBase64)).thenReturn(salt)
    `when`(decoderBase64.decode(hashBase64)).thenReturn(hash)
    `when`(userAuthorizationHashComputer.computeHash(password.toByteArray(), salt)).thenReturn(computedHash)

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
    val hash = byteArrayOf(4, 5, 6)
    val computedHash = byteArrayOf(7, 8, 9) // Different hash

    `when`(userByLoginGetter.get(login)).thenReturn(Ok(UserData(userId, hashBase64, saltBase64)))
    `when`(decoderBase64.decode(saltBase64)).thenReturn(salt)
    `when`(decoderBase64.decode(hashBase64)).thenReturn(hash)
    `when`(userAuthorizationHashComputer.computeHash(password.toByteArray(), salt)).thenReturn(computedHash)

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
