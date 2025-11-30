package ru.code4a.auth.security.hasher.deprecated

import jakarta.enterprise.context.ApplicationScoped

// Recommended params for scrypt: https://cryptobook.nakov.com/mac-and-key-derivation/scrypt
@Deprecated("Use custom PrefixedPasswordHasher instead")
@ApplicationScoped
class HasherBytesScryptWithRecommendedParamsForAuth {
  private val hasher = HasherBytesScrypt(16384, 8, 1, 512)

  fun hash(
    input: ByteArray,
    salt: ByteArray
  ): ByteArray = hasher.hash(input, salt)
}
