package ru.code4a.auth

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.security.SecureBytesGeneratorStrong
import ru.code4a.auth.security.UserAuthorizationHashComputer

@ApplicationScoped
class AuthorizationDataUserCreator(
  private val userAuthorizationHashComputer: UserAuthorizationHashComputer,
  private val secureBytesGeneratorStrong: SecureBytesGeneratorStrong,
  private val encoderBase64: EncoderBase64
) {
  data class AuthorizationData(
    val userAuthorizationHashBase64: String,
    val authorizationSaltBase64: String
  )

  fun compute(password: String): AuthorizationData {
    val authorizationSaltBytes = secureBytesGeneratorStrong.generate(128 / 8)

    val userAuthorizationHashBytes =
      userAuthorizationHashComputer.computeHash(
        password.toByteArray(),
        authorizationSaltBytes
      )

    return AuthorizationData(
      userAuthorizationHashBase64 = encoderBase64.encode(userAuthorizationHashBytes),
      authorizationSaltBase64 = encoderBase64.encode(authorizationSaltBytes)
    )
  }
}
