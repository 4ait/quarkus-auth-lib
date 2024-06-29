package ru.code4a.auth.test.encode

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import ru.code4a.auth.encoding.DecoderBase64
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.security.SecureBytesGeneratorStrong

class Base64EncodeDecode {
  @Test
  fun test() {
    val bytes = SecureBytesGeneratorStrong().generate(128 / 8)
    val bytes1 = SecureBytesGeneratorStrong().generate(512 / 8)

    val encodeString = EncoderBase64().encode(bytes)
    val encodeString1 = EncoderBase64().encode(bytes1)

    println(encodeString)
    println(encodeString1)

    val decodedByteArray = DecoderBase64().decode(encodeString)
    val decodedByteArray1 = DecoderBase64().decode(encodeString1)

    Assertions.assertArrayEquals(decodedByteArray, bytes)
    Assertions.assertArrayEquals(decodedByteArray1, bytes1)
  }
}
