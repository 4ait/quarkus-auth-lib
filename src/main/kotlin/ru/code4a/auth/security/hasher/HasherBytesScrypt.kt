package ru.code4a.auth.security.hasher

import com.lambdaworks.crypto.SCrypt

/**
 * Implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt KDF</a>.
 * Calls the native implementation {@link #scryptN} when the native library was successfully
 * loaded, otherwise calls {@link #scryptJ}.
 *
 * @param passwd    Password.
 * @param salt      Salt.
 * @param N         CPU cost parameter.
 * @param r         Memory cost parameter.
 * @param p         Parallelization parameter.
 * @param dkLen     Intended length of the derived key.
 *
 * @return The derived key.
 *
 * @throws GeneralSecurityException when HMAC_SHA256 is not available.
 */
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
