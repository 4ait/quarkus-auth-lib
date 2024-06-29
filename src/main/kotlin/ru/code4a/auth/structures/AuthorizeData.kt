package ru.code4a.auth.structures

import java.time.Instant

data class AuthorizeData(
  val userId: Long,
  val sessionUserTokenBase64: String,
  val sessionCsrfTokenBase64: String,
  val validUntil: Instant
)
