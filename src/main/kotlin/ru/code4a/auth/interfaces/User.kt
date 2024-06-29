package ru.code4a.auth.interfaces

interface User {
  val id: Long
  val authorizationHashBase64: String
  val authorizationSaltBase64: String
}
