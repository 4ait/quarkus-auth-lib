package ru.code4a.auth.interfaces

/**
 * Salted hash implementation that is chosen by prefix.
 *
 * The prefix is written together with the resulting hash so that verification can
 * select the same implementation. Mark [isPrimary] when this hasher should be used
 * for producing new hashes.
 */
interface AuthPrefixedSaltedHasher {
  val prefix: String

  val isPrimary: Boolean
    get() = false

  fun hash(
    input: ByteArray,
    salt: ByteArray
  ): ByteArray
}
