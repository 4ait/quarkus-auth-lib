package ru.code4a.auth.security.ciphers.aesgcm

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.security.SecureBytesGeneratorStrong

@ApplicationScoped
class CipherAESGCMIVMSG(
  private val cipherAESGCM: CipherAESGCM,
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
      cipherAESGCM.encrypt(
        salt + input,
        key,
        iv,
        ivLengthBits
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
      cipherAESGCM.decrypt(
        encryptedData,
        key,
        iv,
        ivLengthBits
      )

    return decryptedData.copyOfRange(saltSizeBytes, decryptedData.size)
  }
}
