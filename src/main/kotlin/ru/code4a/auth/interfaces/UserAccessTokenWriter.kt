package ru.code4a.auth.interfaces

import java.time.Instant

interface UserAccessTokenWriter {
  fun write(
    userSessionId: Long,
    userSessionTokenId: Long,
    sessionPublicTokenBase64: String,
    validUntil: Instant
  )
}
