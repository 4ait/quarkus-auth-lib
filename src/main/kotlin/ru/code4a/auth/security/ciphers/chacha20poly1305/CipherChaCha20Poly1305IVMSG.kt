package ru.code4a.auth.security.ciphers.chacha20poly1305

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.security.SecureBytesGeneratorStrong

/**
 * CipherChaCha20Poly1305IVMSG provides utilities to perform encryption and decryption operations
 * using the ChaCha20-Poly1305 cipher algorithm. This class encapsulates functionality to handle
 * initialization vectors (IV) and salts securely, ensuring encryption integrity and confidentiality.
 */
@ApplicationScoped
class CipherChaCha20Poly1305IVMSG(
  private val cipherChaCha20Poly1305: CipherChaCha20Poly1305,
  private val secureBytesGeneratorStrong: SecureBytesGeneratorStrong
) {
  /**
   * Encrypts the provided input data using ChaCha20-Poly1305 cipher with a given key and IV.
   * Additionally, it prepends a securely generated random salt to the input before encryption.
   * The result contains IV concatenated with the encrypted data (salt + original input).
   *
   * @param input Input data to be encrypted as ByteArray.
   * @param key Encryption key as ByteArray.
   * @param iv Initialization vector (nonce) as ByteArray.
   * @param saltSizeBytes Size in bytes of random salt to generate and prepend.
   * @return ByteArray containing concatenation of IV and encrypted (salt + input).
   */
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

  /**
   * Encrypts the provided input data using ChaCha20-Poly1305 cipher without adding salt.
   * The result contains IV concatenated with the encrypted data (input).
   *
   * @param input Input data to be encrypted as ByteArray.
   * @param key Encryption key as ByteArray.
   * @param iv Initialization vector (nonce) as ByteArray.
   * @return ByteArray containing concatenation of IV and encrypted input.
   */
  fun encryptWithIv(
    input: ByteArray,
    key: ByteArray,
    iv: ByteArray
  ): ByteArray {
    return iv +
      cipherChaCha20Poly1305.encrypt(
        input,
        key,
        iv
      )
  }

  /**
   * Decrypts data that was encrypted using 'encryptWithIv' method with salt.
   * Extracts IV and salt from encrypted data to perform decryption.
   *
   * @param input Encrypted data containing IV followed by ciphertext (salt + original input).
   * @param key Encryption key as ByteArray.
   * @param ivLengthBits Length of IV used during encryption (in bits).
   * @param saltSizeBytes Size of salt that was generated and prepended before encryption.
   * @return Original decrypted ByteArray without IV and salt.
   */
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

  /**
   * Decrypts data that was encrypted using 'encryptWithIv' method WITHOUT salt.
   * Extracts IV from encrypted data to perform decryption.
   *
   * @param input Encrypted data containing IV followed by ciphertext.
   * @param key Encryption key as ByteArray.
   * @param ivLengthBits Length of IV used during encryption (in bits).
   * @return Original decrypted ByteArray without IV.
   */
  fun decrypt(
    input: ByteArray,
    key: ByteArray,
    ivLengthBits: Int
  ): ByteArray {
    val encryptedData = input.copyOfRange(ivLengthBits / 8, input.size)
    val iv = input.copyOfRange(0, ivLengthBits / 8)

    val decryptedData =
      cipherChaCha20Poly1305.decrypt(
        encryptedData,
        key,
        iv
      )

    return decryptedData
  }
}
