package ru.code4a.auth.security.ciphers.aescbc

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.security.SecureBytesGeneratorStrong

@ApplicationScoped
class CipherAESCBCIVMSG(
  private val cipherAESCBC: CipherAESCBC,
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
      cipherAESCBC.encrypt(
        salt + input,
        key,
        iv
      )
  }

  fun encryptWithIV(
    input: ByteArray,
    key: ByteArray,
    iv: ByteArray,
    saltSizeBytes: Int
  ): ByteArray {
    val salt = secureBytesGeneratorStrong.generate(saltSizeBytes)

    return iv +
      cipherAESCBC.encrypt(
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
      cipherAESCBC.decrypt(
        encryptedData,
        key,
        iv
      )

    return decryptedData.copyOfRange(saltSizeBytes, decryptedData.size)
  }
}
