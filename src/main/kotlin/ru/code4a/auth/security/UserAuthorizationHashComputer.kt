package ru.code4a.auth.security

import jakarta.annotation.PostConstruct
import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.inject.ConfigProperty
import ru.code4a.auth.security.hasher.HasherBytesSHA512
import ru.code4a.auth.security.hasher.HasherBytesScryptWithRecommendedParamsForAuth

@ApplicationScoped
class UserAuthorizationHashComputer(
  private val scrypt: HasherBytesScryptWithRecommendedParamsForAuth,
  private val sha512: HasherBytesSHA512
) {
  @ConfigProperty(name = "foura.fauth.authorization-hash-salt")
  private lateinit var authorizationHashSalt: String

  private lateinit var applicationAuthorizationPasswordSaltRound1: ByteArray
  private lateinit var applicationAuthorizationPasswordSaltRound2: ByteArray

  @PostConstruct
  protected fun init() {
    val applicationAuthorizationPasswordSalt = authorizationHashSalt.toByteArray()

    applicationAuthorizationPasswordSaltRound1 =
      applicationAuthorizationPasswordSalt.copyOfRange(0, applicationAuthorizationPasswordSalt.size / 2)

    applicationAuthorizationPasswordSaltRound2 =
      applicationAuthorizationPasswordSalt.copyOfRange(
        applicationAuthorizationPasswordSalt.size / 2,
        applicationAuthorizationPasswordSalt.size
      )
  }

  fun computeHash(
    password: ByteArray,
    authorizationSalt: ByteArray
  ): ByteArray =
    sha512.hash(
      scrypt.hash(
        sha512.hash(
          password,
          authorizationSalt
        ),
        applicationAuthorizationPasswordSaltRound1
      ),
      applicationAuthorizationPasswordSaltRound2
    )
}
