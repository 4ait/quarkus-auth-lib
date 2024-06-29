package ru.code4a.auth.security.hasher

interface HasherBytes {
  fun hash(
    input: ByteArray,
    salt: ByteArray
  ): ByteArray
}
