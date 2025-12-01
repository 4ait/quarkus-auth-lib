package ru.code4a.auth.interfaces

/**
 * Dedicated password hasher chosen by prefix.
 *
 * This interface is separated from generic salted hashers to allow using
 * slower / more expensive algorithms specifically for password protection.
 */
interface AuthPrefixedPasswordHasher {
  val prefix: String

 val isPrimary: Boolean
    get() = false

  fun hash(
    password: String,
    salt: ByteArray
  ): ByteArray

  fun matches(
    hash: ByteArray,
    password: String,
    salt: ByteArray
  ): Boolean =
    java.security.MessageDigest.isEqual(
      hash,
      this.hash(password, salt)
    )
}
