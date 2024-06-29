package ru.code4a.auth.structures

import ru.code4a.auth.interfaces.User

data class UserData(
  override val id: Long,
  override val authorizationHashBase64: String,
  override val authorizationSaltBase64: String
) : User
