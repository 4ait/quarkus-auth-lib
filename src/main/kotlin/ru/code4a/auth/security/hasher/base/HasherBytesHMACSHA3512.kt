package ru.code4a.auth.security.hasher.base

import io.quarkus.arc.properties.IfBuildProperty
import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.security.hasher.HasherBytes
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

@ApplicationScoped
@IfBuildProperty( name = "foura.fauth.base-hash-alg", stringValue = "HmacSHA3-512")
class HasherBytesHMACSHA3512 : HasherBytes, BaseAuthHasherBytes {
  override fun hash(input: ByteArray, salt: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA3-512")
    val secretKey = SecretKeySpec(salt, "HmacSHA3-512")
    mac.init(secretKey)
    return mac.doFinal(input)
  }
}
