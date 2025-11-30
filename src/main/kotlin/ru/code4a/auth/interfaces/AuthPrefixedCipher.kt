package ru.code4a.auth.interfaces

/**
 * Cipher that can be selected by string prefix.
 *
 * The prefix is stored alongside the encrypted payload so that the correct implementation
 * can be selected for decryption. Set [isPrimary] to true to make this cipher the default
 * choice for encryption if multiple implementations are present.
 */
interface AuthPrefixedCipher {
  val prefix: String

  val isPrimary: Boolean
    get() = false

  fun encrypt(input: ByteArray): ByteArray

  fun decrypt(input: ByteArray): ByteArray
}
