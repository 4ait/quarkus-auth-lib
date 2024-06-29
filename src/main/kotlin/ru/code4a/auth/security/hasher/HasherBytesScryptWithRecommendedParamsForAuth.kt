package ru.code4a.auth.security.hasher

import jakarta.enterprise.context.ApplicationScoped

// Recommended params for scrypt: https://cryptobook.nakov.com/mac-and-key-derivation/scrypt

@ApplicationScoped
class HasherBytesScryptWithRecommendedParamsForAuth : HasherBytes {
  companion object {
    private val hasher =
      ThreadLocal.withInitial {
        HasherBytesScrypt(16384, 8, 1, 512)
      }
  }

  override fun hash(
    input: ByteArray,
    salt: ByteArray
  ): ByteArray = hasher.get().hash(input, salt)
}
