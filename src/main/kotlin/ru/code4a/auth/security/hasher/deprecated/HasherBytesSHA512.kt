package ru.code4a.auth.security.hasher.deprecated

import io.quarkus.arc.properties.IfBuildProperty
import jakarta.enterprise.context.ApplicationScoped
import ru.code4a.auth.security.hasher.HasherBytes
import java.security.MessageDigest

@ApplicationScoped
@Deprecated("Use custom PrefixedSaltedHasher or PrefixedPasswordHasher instead")
@IfBuildProperty(name = "foura.fauth.base-hash-alg", stringValue = "SHA-512", enableIfMissing = true)
class HasherBytesSHA512 : HasherBytes, BaseAuthHasherBytes {
  override fun hash(
    input: ByteArray,
    salt: ByteArray
  ): ByteArray {
    val digest = MessageDigest.getInstance("SHA-512")
    val output = digest.digest(input)
    digest.update(salt)
    digest.update(output)
    return digest.digest()
  }
}
