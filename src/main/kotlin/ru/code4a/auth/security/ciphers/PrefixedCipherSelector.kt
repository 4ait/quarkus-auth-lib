package ru.code4a.auth.security.ciphers

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.security.PrefixedCryptoResolver
import ru.code4a.auth.security.buildPrefixedValue
import ru.code4a.auth.security.splitPrefixedValue
import java.util.Base64

@ApplicationScoped
class PrefixedCipherSelector(
  private val encoderBase64: EncoderBase64,
  private val decoderBase64: DecoderBase64,
  private val prefixedCryptoResolver: PrefixedCryptoResolver,
  private val fallbackCipher: CipherSessionUserToken
) {
  private val urlEncoder = Base64.getUrlEncoder().withoutPadding()
  private val urlDecoder = Base64.getUrlDecoder()

  fun encryptWithPossiblePrefix(data: ByteArray): String {
    val cipher = prefixedCryptoResolver.tryGetRegisteredCipher()

    return if (cipher != null) {
      buildPrefixedValue(
        prefix = cipher.prefix,
        payload = urlEncoder.encodeToString(cipher.encrypt(data))
      )
    } else {
      encoderBase64.encode(fallbackCipher.encrypt(data))
    }
  }

  fun decryptWithPossiblePrefix(raw: String): ByteArray {
    val (prefix, payload) = splitPrefixedValue(raw)

    val cipherBytes =
      if (prefix != null) {
        urlDecoder.decode(payload)
      } else {
        decoderBase64.decode(payload)
      }

    return prefix
      ?.let { prefixedCryptoResolver.cipherByPrefix(it)?.decrypt(cipherBytes) }
      ?: fallbackCipher.decrypt(cipherBytes)
  }
}
