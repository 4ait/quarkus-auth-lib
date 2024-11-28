package ru.code4a.auth.security.ciphers.chacha20poly1305

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.security.SecureBytesGeneratorStrong

@ApplicationScoped
class CipherChaCha20Poly1305IVMSG(
  private val cipherChaCha20Poly1305: CipherChaCha20Poly1305,
  private val secureBytesGeneratorStrong: SecureBytesGeneratorStrong
) {
  fun encrypt(
    input: ByteArray,
    key: ByteArray,
    ivLengthBits: Int,
    saltSizeBytes: Int
  ): ByteArray {
    val salt = secureBytesGeneratorStrong.generate(saltSizeBytes)
    val iv = secureBytesGeneratorStrong.generate(ivLengthBits / 8)

    return iv +
      cipherChaCha20Poly1305.encrypt(
        salt + input,
        key,
        iv
      )
  }

  fun encryptWithIv(
    input: ByteArray,
    key: ByteArray,
    iv: ByteArray,
    saltSizeBytes: Int
  ): ByteArray {
    val salt = secureBytesGeneratorStrong.generate(saltSizeBytes)

    return iv +
      cipherChaCha20Poly1305.encrypt(
        salt + input,
        key,
        iv
      )
  }

  fun decrypt(
    input: ByteArray,
    key: ByteArray,
    ivLengthBits: Int,
    saltSizeBytes: Int
  ): ByteArray {
    val encryptedData = input.copyOfRange(ivLengthBits / 8, input.size)
    val iv = input.copyOfRange(0, ivLengthBits / 8)

    val decryptedData =
      cipherChaCha20Poly1305.decrypt(
        encryptedData,
        key,
        iv
      )

    return decryptedData.copyOfRange(saltSizeBytes, decryptedData.size)
  }
}
