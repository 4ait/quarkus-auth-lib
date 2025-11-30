package ru.code4a.auth.security

import io.quarkus.arc.All
import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.interfaces.AuthPrefixedCipher
import ru.code4a.auth.interfaces.AuthPrefixedPasswordHasher
import ru.code4a.auth.interfaces.AuthPrefixedSaltedHasher

@ApplicationScoped
class PrefixedCryptoResolver(
  @All private val prefixedCiphers: MutableList<AuthPrefixedCipher>,
  @All private val prefixedSaltedHashers: MutableList<AuthPrefixedSaltedHasher>,
  @All private val prefixedPasswordHashers: MutableList<AuthPrefixedPasswordHasher>
) {
  fun tryGetRegisteredCipher(): AuthPrefixedCipher? =
    pickPrimary(prefixedCiphers) { it.isPrimary }

  fun tryGetRegisteredSaltedHasher(): AuthPrefixedSaltedHasher? =
    pickPrimary(prefixedSaltedHashers) { it.isPrimary }

  fun tryGetRegisteredPasswordHasher(): AuthPrefixedPasswordHasher? =
    pickPrimary(prefixedPasswordHashers) { it.isPrimary }

  fun cipherByPrefix(prefix: String): AuthPrefixedCipher? =
    prefixedCiphers.firstOrNull { it.prefix == prefix }

  fun hasherByPrefix(prefix: String): AuthPrefixedSaltedHasher? =
    prefixedSaltedHashers.firstOrNull { it.prefix == prefix }

  fun passwordHasherByPrefix(prefix: String): AuthPrefixedPasswordHasher? =
    prefixedPasswordHashers.firstOrNull { it.prefix == prefix }

  private fun <T> pickPrimary(
    items: List<T>,
    isPrimary: (T) -> Boolean
  ): T? =
    items.firstOrNull(isPrimary) ?: items.firstOrNull()
}
