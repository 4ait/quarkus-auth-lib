package ru.code4a.auth.security

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.security.hasher.PrefixedSaltedHasherSelector
import ru.code4a.auth.security.hasher.deprecated.BaseAuthHasherBytes

@ApplicationScoped
class SessionCsrfTokenCreator(
  private val baseAuthHasherBytes: BaseAuthHasherBytes,
  private val prefixedSaltedHasherSelector: PrefixedSaltedHasherSelector
) {
  fun createBase64Token(
    privateCsrfToken: ByteArray,
    salt: ByteArray
  ): String =
    prefixedSaltedHasherSelector.hashWithPossiblePrefix(
      input = privateCsrfToken,
      salt = salt,
      fallback = { baseAuthHasherBytes.hash(privateCsrfToken, salt) }
    )

  fun verifyBase64Token(
    expectedCsrfTokenBase64: String,
    privateCsrfToken: ByteArray,
    salt: ByteArray
  ): Boolean =
    prefixedSaltedHasherSelector.verifyHash(
      expectedHashBase64 = expectedCsrfTokenBase64,
      input = privateCsrfToken,
      salt = salt,
      fallback = { baseAuthHasherBytes.hash(privateCsrfToken, salt) }
    )
}
