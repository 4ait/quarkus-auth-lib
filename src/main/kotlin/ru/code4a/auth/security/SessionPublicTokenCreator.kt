package ru.code4a.auth.security

import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.ConfigProvider
import ru.code4a.auth.security.hasher.PrefixedSaltedHasherSelector
import ru.code4a.auth.security.hasher.deprecated.BaseAuthHasherBytes

@ApplicationScoped
class SessionPublicTokenCreator(
  private val baseAuthHasherBytes: BaseAuthHasherBytes,
  private val prefixedSaltedHasherSelector: PrefixedSaltedHasherSelector
) {
  private var privateSessionTokenSalt: ByteArray? = null

  companion object {
    private const val GLOBAL_SALT = "ru.code4a.auth.security.SessionPublicTokenCreator+vYaCvxA9o28DnfxPC9zKVMekrESfgKJg0E7ILdPlWJY"
  }

  fun createBase64Token(sessionPrivateTokenBytes: ByteArray): String {
    return prefixedSaltedHasherSelector.hashWithPossiblePrefix(
      input = sessionPrivateTokenBytes,
      salt = GLOBAL_SALT.toByteArray(),
      fallback = {
        val privateSessionTokenSaltBytes = getLegacyPrivateSessionTokenSaltFromConfig()

        baseAuthHasherBytes.hash(
          sessionPrivateTokenBytes,
          privateSessionTokenSaltBytes
        )
      }
    )
  }

  fun verifyBase64Token(
    expectedSessionPublicTokenBase64: String,
    sessionPrivateTokenBytes: ByteArray
  ): Boolean {
    return prefixedSaltedHasherSelector.verifyHash(
      expectedHashBase64 = expectedSessionPublicTokenBase64,
      input = sessionPrivateTokenBytes,
      salt = GLOBAL_SALT.toByteArray(),
      fallback = {
        val privateSessionTokenSaltBytes = getLegacyPrivateSessionTokenSaltFromConfig()

        baseAuthHasherBytes.hash(
          sessionPrivateTokenBytes,
          privateSessionTokenSaltBytes
        )
      }
    )
  }

  private fun getLegacyPrivateSessionTokenSaltFromConfig(): ByteArray {
    val cachedSalt = privateSessionTokenSalt
    if (cachedSalt != null) {
      return cachedSalt
    }

    val salt =
      ConfigProvider.getConfig()
        .getOptionalValue("foura.fauth.private-session-token-salt", String::class.java)
        .orElseThrow {
          IllegalStateException(
            "Property foura.fauth.private-session-token-salt is required when using the built-in session public token hasher"
          )
        }
        .toByteArray()

    privateSessionTokenSalt = salt

    return salt
  }
}
