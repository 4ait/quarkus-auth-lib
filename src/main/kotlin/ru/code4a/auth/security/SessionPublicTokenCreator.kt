package ru.code4a.auth.security

import jakarta.annotation.PostConstruct
import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.inject.ConfigProperty
import ru.code4a.auth.encoding.EncoderBase64
import ru.code4a.auth.security.hasher.base.BaseAuthHasherBytes

@ApplicationScoped
class SessionPublicTokenCreator(
  private val encoderBase64: EncoderBase64,
  private val baseAuthHasherBytes: BaseAuthHasherBytes
) {
  @ConfigProperty(name = "foura.fauth.private-session-token-salt")
  private lateinit var privateSessionTokenSaltRaw: String

  private lateinit var privateSessionTokenSalt: ByteArray

  @PostConstruct
  protected fun init() {
    privateSessionTokenSalt = privateSessionTokenSaltRaw.toByteArray()
  }

  fun createBase64Token(sessionPrivateTokenBytes: ByteArray): String {
    val privateSessionTokenSaltBytes = privateSessionTokenSalt

    val sessionPublicTokenBytes =
      baseAuthHasherBytes.hash(
        sessionPrivateTokenBytes,
        privateSessionTokenSaltBytes
      )

    return encoderBase64.encode(sessionPublicTokenBytes)
  }
}
