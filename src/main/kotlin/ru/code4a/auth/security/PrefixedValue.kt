package ru.code4a.auth.security

private const val PREFIX_DELIMITER = ':'

internal fun buildPrefixedValue(
  prefix: String,
  payload: String
): String = "$prefix$PREFIX_DELIMITER$payload"

internal fun splitPrefixedValue(raw: String): Pair<String?, String> {
  val delimiterIndex = raw.indexOf(PREFIX_DELIMITER)

  if (delimiterIndex > 0) {
    return raw.substring(0, delimiterIndex) to raw.substring(delimiterIndex + 1)
  }

  return null to raw
}
