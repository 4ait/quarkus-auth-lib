package ru.code4a.auth.test

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
import ru.code4a.auth.AuthorizationDataUserCreator
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.security.SecureBytesGeneratorStrong
import ru.code4a.auth.security.UserAuthorizationHashComputer

class AuthorizationDataUserCreatorTest {
  private lateinit var authorizationDataUserCreator: AuthorizationDataUserCreator
  private lateinit var userAuthorizationHashComputer: UserAuthorizationHashComputer
  private lateinit var secureBytesGeneratorStrong: SecureBytesGeneratorStrong
  private lateinit var encoderBase64: EncoderBase64

  @BeforeEach
  fun setup() {
    userAuthorizationHashComputer = mock(UserAuthorizationHashComputer::class.java)
    secureBytesGeneratorStrong = mock(SecureBytesGeneratorStrong::class.java)
    encoderBase64 = mock(EncoderBase64::class.java)

    authorizationDataUserCreator =
      AuthorizationDataUserCreator(
        userAuthorizationHashComputer,
        secureBytesGeneratorStrong,
        encoderBase64
      )
  }

  @Test
  fun testCompute() {
    val password = "testPassword"
    val salt = byteArrayOf(1, 2, 3)
    val hash = byteArrayOf(4, 5, 6)
    val saltBase64 = "saltBase64"
    val hashBase64 = "hashBase64"

    `when`(secureBytesGeneratorStrong.generate(16)).thenReturn(salt)
    `when`(userAuthorizationHashComputer.computeHash(password.toByteArray(), salt)).thenReturn(hash)
    `when`(encoderBase64.encode(salt)).thenReturn(saltBase64)
    `when`(encoderBase64.encode(hash)).thenReturn(hashBase64)

    val result = authorizationDataUserCreator.compute(password)

    assertEquals(hashBase64, result.userAuthorizationHashBase64)
    assertEquals(saltBase64, result.authorizationSaltBase64)

    verify(secureBytesGeneratorStrong).generate(16)
    verify(userAuthorizationHashComputer).computeHash(password.toByteArray(), salt)
    verify(encoderBase64).encode(salt)
    verify(encoderBase64).encode(hash)
  }
}
