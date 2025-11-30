package ru.code4a.auth.security.hasher.deprecated

@Deprecated("Use custom PrefixedSaltedHasher or PrefixedPasswordHasher instead")
interface BaseAuthHasherBytes {
  fun hash(
    input: ByteArray,
    salt: ByteArray
  ): ByteArray
}
