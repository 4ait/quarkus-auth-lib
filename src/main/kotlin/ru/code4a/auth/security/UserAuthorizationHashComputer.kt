package ru.code4a.auth.security

import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.ConfigProvider
import ru.code4a.auth.security.hasher.PrefixedPasswordHasherSelector
import ru.code4a.auth.security.hasher.deprecated.BaseAuthHasherBytes
import ru.code4a.auth.security.hasher.deprecated.HasherBytesScryptWithRecommendedParamsForAuth

@ApplicationScoped
class UserAuthorizationHashComputer(
  private val scrypt: HasherBytesScryptWithRecommendedParamsForAuth,
  private val baseAuthHasherBytes: BaseAuthHasherBytes,
  private val prefixedPasswordHasherSelector: PrefixedPasswordHasherSelector
) {
  private var applicationAuthorizationPasswordSaltRound1: ByteArray? = null
  private var applicationAuthorizationPasswordSaltRound2: ByteArray? = null

  fun computeHashBase64(
    password: ByteArray,
    authorizationSalt: ByteArray
  ): String =
    prefixedPasswordHasherSelector.hashWithPossiblePrefix(
      password = password,
      salt = authorizationSalt,
      fallback = {
        computeFallbackHash(
          password,
          authorizationSalt
        )
      }
    )

  fun verifyHashBase64(
    expectedHashBase64: String,
    password: ByteArray,
    authorizationSalt: ByteArray
  ): Boolean =
    prefixedPasswordHasherSelector.verifyHash(
      expectedHashBase64 = expectedHashBase64,
      password = password,
      salt = authorizationSalt,
      fallback = {
        computeFallbackHash(
          password,
          authorizationSalt
        )
      }
    )

  private fun computeFallbackHash(
    password: ByteArray,
    authorizationSalt: ByteArray
  ): ByteArray {
    val (applicationAuthorizationPasswordSaltRound1, applicationAuthorizationPasswordSaltRound2) = getApplicationAuthorizationPasswordSalts()

    return baseAuthHasherBytes.hash(
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

  private fun getApplicationAuthorizationPasswordSalts(): Pair<ByteArray, ByteArray> {
    val cachedSalt1 = applicationAuthorizationPasswordSaltRound1
    val cachedSalt2 = applicationAuthorizationPasswordSaltRound2

    if (cachedSalt1 != null && cachedSalt2 != null) {
      return cachedSalt1 to cachedSalt2
    }

    val authorizationHashSalt =
      ConfigProvider.getConfig()
        .getOptionalValue("foura.fauth.authorization-hash-salt", String::class.java)
        .orElseThrow {
          IllegalStateException(
            "Property foura.fauth.authorization-hash-salt is required when using the built-in password hasher"
          )
        }

    val applicationAuthorizationPasswordSalt = authorizationHashSalt.toByteArray()

    val saltRound1 =
      applicationAuthorizationPasswordSalt.copyOfRange(0, applicationAuthorizationPasswordSalt.size / 2)

    val saltRound2 =
      applicationAuthorizationPasswordSalt.copyOfRange(
        applicationAuthorizationPasswordSalt.size / 2,
        applicationAuthorizationPasswordSalt.size
      )

    applicationAuthorizationPasswordSaltRound1 = saltRound1
    applicationAuthorizationPasswordSaltRound2 = saltRound2

    return saltRound1 to saltRound2
  }
}
