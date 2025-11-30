package ru.code4a.auth.security.hasher

import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.security.PrefixedCryptoResolver
import ru.code4a.auth.security.buildPrefixedValue
import ru.code4a.auth.security.splitPrefixedValue
import java.security.MessageDigest
import java.util.Base64

@ApplicationScoped
class PrefixedPasswordHasherSelector(
  private val encoderBase64: EncoderBase64,
  private val decoderBase64: DecoderBase64,
  private val prefixedCryptoResolver: PrefixedCryptoResolver
) {
  private val urlEncoder = Base64.getUrlEncoder().withoutPadding()
  private val urlDecoder = Base64.getUrlDecoder()

  fun hashWithPossiblePrefix(
    password: ByteArray,
    salt: ByteArray,
    fallback: () -> ByteArray
  ): String {
    val hasher = prefixedCryptoResolver.tryGetRegisteredPasswordHasher()

    return if (hasher != null) {
      buildPrefixedValue(
        prefix = hasher.prefix,
        payload = urlEncoder.encodeToString(hasher.hash(password, salt))
      )
    } else {
      encoderBase64.encode(fallback())
    }
  }

  fun verifyHash(
    expectedHashBase64: String,
    password: ByteArray,
    salt: ByteArray,
    fallback: () -> ByteArray
  ): Boolean {
    val (prefix, payload) = splitPrefixedValue(expectedHashBase64)

    val actualBytes =
      prefix
        ?.let { prefixedCryptoResolver.passwordHasherByPrefix(it) }
        ?.hash(password, salt)
        ?: fallback()

    val expectedBytes =
      if (prefix != null) {
        urlDecoder.decode(payload)
      } else {
        decoderBase64.decode(payload)
      }

    return MessageDigest.isEqual(expectedBytes, actualBytes)
  }
}
