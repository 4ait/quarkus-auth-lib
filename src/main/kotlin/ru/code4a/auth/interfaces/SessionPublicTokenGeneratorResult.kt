package ru.code4a.auth.interfaces

import java.time.Instant

interface SessionPublicTokenGeneratorResult {
  fun getUserSessionTokenId(): Long

  fun getSessionPublicTokenBase64(): String

  fun getSessionUserTokenBase64(): String

  fun getCsrfTokenBase64(): String

  fun getValidUntil(): Instant
}
