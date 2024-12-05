package ru.code4a.auth.interfaces

interface CipherSessionUserTokenIvProducer {
  fun produce(): ByteArray
}
