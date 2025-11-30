# Session Authorization Library

This library provides a robust authorization system for Quarkus applications, implementing secure session management and user authentication.

# Versions

* 0.10.0+ Required Quarkus 3.29.3+

# Features

* User authentication with login and password
* Secure session creation and management
* CSRF token protection
* Access token generation and renewal
* Configurable token expiration
* Pluggable crypto: custom prefixed cipher, salted hashers for tokens, and a dedicated password hasher

# Installation

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>ru.code4a</groupId>
    <artifactId>quarkus-auth</artifactId>
    <version>0.1.0</version>
</dependency>
```

# Configuration

Minimal required configuration:

```properties
# Token validity period in minutes
foura.fauth.minutes-token-valid=60
```

Legacy-only (needed **only** if you rely on deprecated built-in crypto instead of providing custom providers):

```properties
# Base64 encoded secret key for session user tokens (96 bytes)
foura.fauth.secret-session-user-token-key-base64=<your_base64_encoded_secret_key>

# Base64 encoded salt for private session token
foura.fauth.private-session-token-salt=<your_private_session_token_salt>

# Base64 encoded salt for password hash
foura.fauth.authorization-hash-salt=<authorization_hash_salt>
```

These secrets are loaded lazily at runtime and are unused when custom prefixed providers are present.

# Extending crypto

All crypto outputs can be prefixed (`<prefix>:<base64>`) so the library can route to the correct implementation at runtime.

- Implement `AuthPrefixedCipher` for encrypting/decrypting session user tokens. The `isPrimary` implementation will be used for encryption; decryption uses the prefix in the payload.
- Implement `AuthPrefixedSaltedHasher` for hashing/verifying session public tokens and CSRF tokens. The `isPrimary` implementation is used for new hashes.
- Implement `AuthPrefixedPasswordHasher` for hashing/verifying user passwords. The `isPrimary` implementation is used for new password hashes.
- If no matching implementation is found, the library falls back to built-in algorithms located in `ru.code4a.auth.security.hasher.deprecated.*`.
- Prefixed values are encoded with URL-safe Base64 (no padding). Legacy/fallback values keep the existing Base64 alphabet.

# Key Components

## SessionCreatorWithERPAuthAlgorithm

Creates new user sessions with the following security measures:

* Generates secure random bytes for session tokens
* Creates public, user, and CSRF tokens
* Stores session data securely

## SessionRequestNewAccessTokenWithERPAuthAlgorithm

Handles the creation of new access tokens for existing sessions:

* Generates new session private tokens
* Updates session storage with new token information
* Configurable token validity period

## UserAuthorizerByLoginPasswordWithERPAuthAlgorithm

Manages user authorization using login and password:

* Verifies user credentials against stored authorization hash
* Creates a new session upon successful authentication
* Handles various error scenarios securely

## AuthorizationDataUserCreator

Computes and stores authorization data for new users:

* Generates secure salt for each user
* Computes authorization hash using provided password and salt
* Encodes data for secure storage

## SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm

Authorizes sessions using session user tokens:

* Verifies session validity and expiration
* Optionally checks CSRF token
* Handles various error scenarios, including expired tokens and invalid CSRF

# Usage

To use this library, include it in your Quarkus project and inject the required components.

Here's a basic example of user authentication:

```kotlin
@Inject
lateinit var userAuthorizer: UserAuthorizerByLoginPasswordWithERPAuthAlgorithm

// ... in your authentication endpoint
val authResult = userAuthorizer.authorizeUserByLoginPassword(
    userByLoginGetter,
    userSessionTokenNewIdGetter,
    userSessionStorageWriter,
    login,
    password
)

when (authResult) {
    is Ok -> // Handle successful authentication
    is Error -> // Handle authentication error
}
```

# Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

# License

Apache 2.0
