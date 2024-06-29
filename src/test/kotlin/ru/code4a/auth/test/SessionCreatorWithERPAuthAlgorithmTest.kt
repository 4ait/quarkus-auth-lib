package ru.code4a.auth.test

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
import ru.code4a.auth.SessionCreatorWithERPAuthAlgorithm
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.interfaces.UserSessionStorageWriter
import ru.code4a.auth.interfaces.UserSessionTokenNewIdGetter
import ru.code4a.auth.security.SecureBytesGeneratorStrong
import ru.code4a.auth.security.SessionCsrfTokenCreator
import ru.code4a.auth.security.SessionPublicTokenCreator
import ru.code4a.auth.security.SessionUserTokenCreator
import ru.code4a.errorhandling.Ok
import java.time.Instant

class SessionCreatorWithERPAuthAlgorithmTest {
  private lateinit var sessionCreator: SessionCreatorWithERPAuthAlgorithm
  private lateinit var secureBytesGenerator: SecureBytesGeneratorStrong
  private lateinit var sessionUserTokenCreator: SessionUserTokenCreator
  private lateinit var sessionCsrfTokenCreator: SessionCsrfTokenCreator
  private lateinit var sessionPublicTokenCreator: SessionPublicTokenCreator
  private lateinit var base64: EncoderBase64
  private lateinit var userSessionTokenNewIdGetter: UserSessionTokenNewIdGetter
  private lateinit var userSessionStorageWriter: UserSessionStorageWriter

  @BeforeEach
  fun setup() {
    secureBytesGenerator = mock(SecureBytesGeneratorStrong::class.java)
    sessionUserTokenCreator = mock(SessionUserTokenCreator::class.java)
    sessionCsrfTokenCreator = mock(SessionCsrfTokenCreator::class.java)
    sessionPublicTokenCreator = mock(SessionPublicTokenCreator::class.java)
    base64 = mock(EncoderBase64::class.java)
    userSessionTokenNewIdGetter = mock(UserSessionTokenNewIdGetter::class.java)
    userSessionStorageWriter = mock(UserSessionStorageWriter::class.java)

    sessionCreator =
      SessionCreatorWithERPAuthAlgorithm(
        secureBytesGenerator,
        sessionUserTokenCreator,
        sessionCsrfTokenCreator,
        sessionPublicTokenCreator,
        base64
      )
  }

  private inline fun <reified T> any(): T = any(T::class.java)

  @Test
  fun testCreateSession() {
    val userId = 1L
    val userSessionTokenId = 2L
    val authorizedAt = Instant.now()
    val validUntil = authorizedAt.plusSeconds(3600)
    val sessionPrivateTokenBytes = byteArrayOf(1, 2, 3)
    val sessionPrivateCsrfTokenBytes = byteArrayOf(4, 5, 6)
    val sessionCsrfTokenSaltBytes = byteArrayOf(7, 8, 9)
    val sessionPublicTokenBase64 = "publicToken"
    val sessionUserTokenBase64 = "userToken"
    val sessionCsrfTokenBase64 = "csrfToken"
    val sessionCsrfTokenSaltBase64 = "csrfSalt"

    `when`(secureBytesGenerator.generate(64)).thenReturn(sessionPrivateTokenBytes)
    `when`(secureBytesGenerator.generate(32)).thenReturn(sessionPrivateCsrfTokenBytes, sessionCsrfTokenSaltBytes)
    `when`(sessionPublicTokenCreator.createBase64Token(sessionPrivateTokenBytes)).thenReturn(sessionPublicTokenBase64)
    `when`(sessionUserTokenCreator.createBase64Token(userSessionTokenId, sessionPrivateTokenBytes, sessionPrivateCsrfTokenBytes))
      .thenReturn(sessionUserTokenBase64)
    `when`(sessionCsrfTokenCreator.createBase64Token(sessionPrivateCsrfTokenBytes, sessionCsrfTokenSaltBytes))
      .thenReturn(sessionCsrfTokenBase64)
    `when`(base64.encode(sessionCsrfTokenSaltBytes)).thenReturn(sessionCsrfTokenSaltBase64)
    `when`(userSessionStorageWriter.write(any(), any(), any(), any(), any(), any())).thenReturn(Ok(Unit))
    `when`(userSessionTokenNewIdGetter.with<Long>(any())).thenAnswer { invocation ->
      val block = invocation.getArgument<(Long) -> Any>(0)
      block(userSessionTokenId)
    }

    val result =
      sessionCreator.createSession(
        userSessionTokenNewIdGetter,
        userSessionStorageWriter,
        userId,
        authorizedAt,
        validUntil
      )

    assertEquals(userSessionTokenId, result.getUserSessionTokenId())
    assertEquals(sessionPublicTokenBase64, result.getSessionPublicTokenBase64())
    assertEquals(sessionUserTokenBase64, result.getSessionUserTokenBase64())
    assertEquals(sessionCsrfTokenBase64, result.getCsrfTokenBase64())
    assertEquals(validUntil, result.getValidUntil())

    verify(userSessionStorageWriter).write(
      userId,
      userSessionTokenId,
      sessionPublicTokenBase64,
      sessionCsrfTokenSaltBase64,
      authorizedAt,
      validUntil
    )
  }
}
