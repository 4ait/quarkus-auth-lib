package ru.code4a.auth.security.hasher.base

interface BaseAuthHasherBytes {
  fun hash(
    input: ByteArray,
    salt: ByteArray
  ): ByteArray
}
