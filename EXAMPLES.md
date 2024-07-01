# Usage Examples

This document provides detailed examples of how to use the main components of the Quarkus Authorization Library.

## User Registration

To register a new user and create their authorization data:

```kotlin
@Inject
lateinit var authDataCreator: AuthorizationDataUserCreator

fun registerUser(username: String, password: String) {
    val authData = authDataCreator.compute(password)

    // Store the username, authData.userAuthorizationHashBase64,
    // and authData.authorizationSaltBase64 in your user database
}
```

## User Authentication

Authenticating a user with their login and password:

```kotlin
@Inject
lateinit var userAuthorizer: UserAuthorizerByLoginPasswordWithERPAuthAlgorithm

fun authenticateUser(login: String, password: String): AuthorizeData? {
    val authResult = userAuthorizer.authorizeUserByLoginPassword(
        userByLoginGetter,
        userSessionTokenNewIdGetter,
        userSessionStorageWriter,
        login,
        password
    )

    return when (authResult) {
        is Ok -> {
            val authorizeData = authResult.value
            // Store or return session tokens
            authorizeData
        }
        is Error -> {
            // Handle authentication failure
            null
        }
    }
}
```

## Session Authorization

Authorizing a user's session using their session token:

```kotlin
@Inject
lateinit var sessionAuthorizer: SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm

fun authorizeSession(sessionUserToken: String, csrfToken: String?): Boolean {
    val authResult = sessionAuthorizer.authorizeBySessionUserToken(
        userSessionStorageGetter,
        verifyCsrfToken = true,
        sessionUserTokenBase64 = sessionUserToken,
        sessionCsrfTokenBase64 = csrfToken
    )

    return when (authResult) {
        is Ok -> true
        is Error -> {
            when (authResult.error) {
                is SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.AuthorizeSessionError.SessionNotAuthorized ->
                    // Handle unauthorized session
                is SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.AuthorizeSessionError.AccessTokenExpired ->
                    // Handle expired token
                is SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.AuthorizeSessionError.CSRFTokenIsNotFound ->
                    // Handle missing CSRF token
                is SessionAuthorizerBySessionUserTokenWithERPAuthAlgorithm.AuthorizeSessionError.CSRFTokenIsNotValid ->
                    // Handle invalid CSRF token
            }
            false
        }
    }
}
```

## Renewing Access Token

When a user's access token is about to expire, you can renew it:

```kotlin
@Inject
lateinit var tokenRenewer: SessionRequestNewAccessTokenWithERPAuthAlgorithm

fun renewAccessToken(userSessionId: Long, currentSessionUserToken: String): NewAccessTokenData? {
    return try {
        tokenRenewer.requestNewUserAccessToken(
            userSessionTokenNewIdGetter,
            userAccessTokenWriter,
            userSessionId,
            currentSessionUserToken
        )
    } catch (e: Exception) {
        // Handle token renewal failure
        null
    }
}
```

## Creating a New Session

If you need to create a new session manually:

```kotlin
@Inject
lateinit var sessionCreator: SessionCreatorWithERPAuthAlgorithm

fun createNewSession(userId: Long): SessionPublicTokenGeneratorResult {
    val now = Instant.now()
    return sessionCreator.createSession(
        userSessionTokenNewIdGetter,
        userSessionStorageWriter,
        userId,
        authorizedAt = now,
        validUntil = now.plus(Duration.ofHours(24))
    )
}
```

## Implementing Required Interfaces

To use this library, you need to implement several interfaces. Here are basic examples:

### UserByLoginGetter

```kotlin
class MyUserByLoginGetter : UserByLoginGetter {
    override fun get(login: String): OkOrError<UserByLoginGetter.UserData, UserByLoginGetter.GetError> {
        // Fetch user data from your database
        // Return Ok(userData) if found, or Error(UserByLoginGetter.GetError) if not
    }
}
```

### UserSessionStorageWriter

```kotlin
class MyUserSessionStorageWriter : UserSessionStorageWriter {
    override fun write(
        userId: Long,
        userSessionTokenId: Long,
        sessionPublicTokenBase64: String,
        sessionCsrfTokenSaltBase64: String,
        authorizedAt: Instant,
        validUntil: Instant
    ): OkOrError<Unit, UserSessionStorageWriter.WriteError> {
        // Write session data to your storage
        // Return Ok(Unit) on success, or Error(WriteError) on failure
    }
}
```

### UserSessionTokenNewIdGetter

```kotlin
class MyUserSessionTokenNewIdGetter : UserSessionTokenNewIdGetter {
    override fun <T> with(block: (Long) -> T): T {
        // Generate or fetch a new unique session token ID
        val newId = generateNewId()
        return block(newId)
    }
}
```
