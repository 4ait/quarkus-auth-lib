package ru.code4a.auth.test

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
import ru.code4a.auth.SessionRequestNewAccessTokenWithERPAuthAlgorithm
import ru.code4a.auth.interfaces.UserAccessTokenWriter
import ru.code4a.auth.interfaces.UserSessionTokenNewIdGetter
import ru.code4a.auth.security.SecureBytesGeneratorStrong
import ru.code4a.auth.security.SessionPublicTokenCreator
import ru.code4a.auth.security.SessionUserTokenCreator
import java.time.Instant

class SessionRequestNewAccessTokenWithERPAuthAlgorithmTest {
  private lateinit var sessionRequestNewAccessToken: SessionRequestNewAccessTokenWithERPAuthAlgorithm
  private lateinit var sessionUserTokenCreator: SessionUserTokenCreator
  private lateinit var secureBytesGeneratorStrong: SecureBytesGeneratorStrong
  private lateinit var sessionPublicTokenCreator: SessionPublicTokenCreator
  private lateinit var userSessionTokenNewIdGetter: UserSessionTokenNewIdGetter
  private lateinit var userAccessTokenWriter: UserAccessTokenWriter

  @BeforeEach
  fun setup() {
    sessionUserTokenCreator = mock(SessionUserTokenCreator::class.java)
    secureBytesGeneratorStrong = mock(SecureBytesGeneratorStrong::class.java)
    sessionPublicTokenCreator = mock(SessionPublicTokenCreator::class.java)
    userSessionTokenNewIdGetter = mock(UserSessionTokenNewIdGetter::class.java)
    userAccessTokenWriter = mock(UserAccessTokenWriter::class.java)

    sessionRequestNewAccessToken =
      SessionRequestNewAccessTokenWithERPAuthAlgorithm(
        sessionUserTokenCreator,
        secureBytesGeneratorStrong,
        sessionPublicTokenCreator
      )

    // Set minutesTokenValid using reflection for testing
    val field = SessionRequestNewAccessTokenWithERPAuthAlgorithm::class.java.getDeclaredField("minutesTokenValid")
    field.isAccessible = true
    field.set(sessionRequestNewAccessToken, 60L)
  }

  private inline fun <reified T> any(): T = any(T::class.java)

  @Test
  fun testRequestNewUserAccessToken() {
    val userSessionId = 1L
    val oldSessionUserTokenBase64 = "oldUserToken"
    val newUserSessionTokenId = 2L
    val oldSessionUserTokenData =
      SessionUserTokenCreator.TokenData(
        1L,
        byteArrayOf(1, 2, 3),
        byteArrayOf(4, 5, 6)
      )
    val newSessionPrivateTokenBytes = byteArrayOf(7, 8, 9)
    val newSessionUserTokenBase64 = "newUserToken"
    val newSessionPublicTokenBase64 = "newPublicToken"

    `when`(sessionUserTokenCreator.unpackBase64Token(oldSessionUserTokenBase64)).thenReturn(oldSessionUserTokenData)
    `when`(secureBytesGeneratorStrong.generate(64)).thenReturn(newSessionPrivateTokenBytes)
    `when`(
      sessionUserTokenCreator.createBase64Token(
        newUserSessionTokenId,
        newSessionPrivateTokenBytes,
        oldSessionUserTokenData.sessionPrivateCsrfTokenBytes
      )
    ).thenReturn(newSessionUserTokenBase64)
    `when`(sessionPublicTokenCreator.createBase64Token(newSessionPrivateTokenBytes)).thenReturn(newSessionPublicTokenBase64)
    `when`(userSessionTokenNewIdGetter.with<Long>(any())).thenAnswer { invocation ->
      val block = invocation.getArgument<(Long) -> Any>(0)
      block(newUserSessionTokenId)
    }

    val result =
      sessionRequestNewAccessToken.requestNewUserAccessToken(
        userSessionTokenNewIdGetter,
        userAccessTokenWriter,
        userSessionId,
        oldSessionUserTokenBase64
      )

    assertEquals(newSessionUserTokenBase64, result.sessionUserTokenBase64)
    assertEquals(newUserSessionTokenId, result.userSessionTokenId)
    assertTrue(result.validUntil.isAfter(Instant.now()))

    verify(userAccessTokenWriter).write(
      userSessionId,
      newUserSessionTokenId,
      newSessionPublicTokenBase64,
      result.validUntil
    )
  }
}
