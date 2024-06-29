package ru.code4a.auth.test.security

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import ru.code4a.auth.security.SecureBytesGeneratorStrong
import ru.code4a.auth.security.hasher.HasherBytesScryptWithRecommendedParamsForAuth

class HashBytesWithSCrypt {
  @Test
  fun test() {
    val privateToken = SecureBytesGeneratorStrong().generate(512 / 8)
    val salt = ByteArray(128 / 8)

    val publicToken =
      HasherBytesScryptWithRecommendedParamsForAuth().hash(
        privateToken,
        salt
      )

    val recommendedOutputSize = 512
    Assertions.assertEquals(recommendedOutputSize, publicToken.size)
  }
}
