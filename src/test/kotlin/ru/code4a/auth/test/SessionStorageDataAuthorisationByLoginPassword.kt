package ru.code4a.auth.test

import org.junit.jupiter.api.Test
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.security.hasher.HasherBytesScryptWithRecommendedParamsForAuth

class SessionStorageDataAuthorisationByLoginPassword {
  @Test
  fun failedAuthorizeUserByLoginPassword() {
    val authorizationSalt = "nF4FvOInTZw="
    val password = "test"

    println(authorizationSalt)
    println(DecoderBase64().decode(authorizationSalt))
    println(DecoderBase64().decode(authorizationSalt).size)

    val salt = DecoderBase64().decode(authorizationSalt) + byteArrayOf(49, 50, 51, 49, 50, 51, 49, 50)
    println(salt.size)

    val userAuthorizationHash =
      HasherBytesScryptWithRecommendedParamsForAuth().hash(
        password.toByteArray(),
        DecoderBase64().decode(authorizationSalt) + byteArrayOf(49, 50, 51, 49, 50, 51, 49, 50)
      )

    println(userAuthorizationHash)
    println(userAuthorizationHash.size)
    println(EncoderBase64().encode(userAuthorizationHash))

    assert(true)
  }
}
