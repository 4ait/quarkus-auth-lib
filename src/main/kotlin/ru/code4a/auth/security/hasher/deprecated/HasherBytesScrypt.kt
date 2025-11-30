package ru.code4a.auth.security.hasher.deprecated

import com.lambdaworks.crypto.SCrypt
import ru.code4a.auth.security.hasher.HasherBytes

/**
 * Deprecated fallback scrypt implementation used by built-in password hashing pipeline.
 */
@Deprecated("Use custom PrefixedPasswordHasher instead")
class HasherBytesScrypt(
  val n: Int,
  val r: Int,
  val p: Int,
  val dkLen: Int
) : HasherBytes {
  override fun hash(
    input: ByteArray,
    salt: ByteArray
  ): ByteArray = SCrypt.scrypt(input, salt, n, r, p, dkLen)
}
