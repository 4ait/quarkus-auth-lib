package ru.code4a.auth.interfaces

interface UserSessionTokenNewIdGetter {
  fun <T> with(block: (userSessionTokenId: Long) -> T): T
}
