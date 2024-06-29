package ru.code4a.auth.interfaces

import ru.code4a.errorhandling.OkOrError
import java.time.Instant

interface UserSessionStorageWriter {
  fun write(
    userId: Long,
    userSessionTokenId: Long,
    sessionPublicTokenBase64: String,
    sessionCsrfTokenSaltBase64: String,
    authorizedAt: Instant,
    validUntil: Instant
  ): OkOrError<Unit, Unit>
}
