package ru.code4a.auth.security

import jakarta.annotation.PostConstruct
import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.inject.ConfigProperty
import ru.code4a.auth.security.hasher.base.BaseAuthHasherBytes
import ru.code4a.auth.security.hasher.HasherBytesScryptWithRecommendedParamsForAuth

@ApplicationScoped
class UserAuthorizationHashComputer(
  private val scrypt: HasherBytesScryptWithRecommendedParamsForAuth,
  private val baseAuthHasherBytes: BaseAuthHasherBytes
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
    baseAuthHasherBytes.hash(
      scrypt.hash(
        baseAuthHasherBytes.hash(
          password,
          authorizationSalt
        ),
        applicationAuthorizationPasswordSaltRound1
      ),
      applicationAuthorizationPasswordSaltRound2
    )
}
