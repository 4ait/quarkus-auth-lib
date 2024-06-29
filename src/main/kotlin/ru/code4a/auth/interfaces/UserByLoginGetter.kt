package ru.code4a.auth.interfaces

import ru.code4a.errorhandling.OkOrError

interface UserByLoginGetter {
  class NotFoundError

  fun get(login: String): OkOrError<User, NotFoundError>
}
