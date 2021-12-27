# Best Practices of JWT and Session Token management - OWASP JWT Cheatsheet and OWASP ASVS (Application Security Verification Standard) v5 guidelines

https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V8-Data-Protection.md

## OWASP ASVS

---

### V8.2 Client-side Data Protection

|     #     | Description                                                                                                                                                                                                                                              |  L1   |  L2   |  L3   |  CWE  |
| :-------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---: | :---: | :---: | :---: |
| **8.2.1** | Verify the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers.                                                                                                                                     |   ✓   |   ✓   |   ✓   |  525  |
| **8.2.2** | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of cookie-based session tokens in cookies and token-based session tokens in sessionStorage. |   ✓   |   ✓   |   ✓   |  922  |
| **8.2.3** | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated.                                                                                                                       |   ✓   |   ✓   |   ✓   |  922  |


https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Session-management.md

### V3.2 Session Binding

|     #     | Description                                                                                                                                               |  L1   |  L2   |  L3   |  CWE  | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :-------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------- | :---: | :---: | :---: | :---: | :-----------------------------------------------------------: |
| **3.2.1** | Verify the application generates a new session token on user authentication. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))      |   ✓   |   ✓   |   ✓   |  384  |                              7.1                              |
| **3.2.2** | Verify that session tokens possess at least 128 bits of entropy. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))                  |   ✓   |   ✓   |   ✓   |  331  |                              7.1                              |
| **3.2.4** | Verify that session tokens are generated using approved cryptographic algorithms. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) |       |   ✓   |   ✓   |  331  |                              7.1                              |

TLS or another secure transport channel is mandatory for session management. This is covered off in the Communications Security chapter.

### V3.3 Session Termination

|     #     | Description                                                                                                                                                                                                                                                                      |   L1    |                         L2                         |                       L3                       |  CWE  | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :-------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-----: | :------------------------------------------------: | :--------------------------------------------: | :---: | :-----------------------------------------------------------: |
| **3.3.1** | Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session, including across relying parties. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))      |    ✓    |                         ✓                          |                       ✓                        |  613  |                              7.1                              |
| **3.3.2** | If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))                                                   | 30 days | 12 hours or 30 minutes of inactivity, 2FA optional | 12 hours or 15 minutes of inactivity, with 2FA |  613  |                              7.2                              |
| **3.3.3** | Verify that the application gives the option to terminate all other active sessions after a successful password change (including change via password reset/recovery), and that this is effective across the application, federated login (if present), and any relying parties. |    ✓    |                         ✓                          |                       ✓                        |  613  |                                                               |
| **3.3.4** | Verify that users are able to view and (having re-entered login credentials) log out of any or all currently active sessions and devices.                                                                                                                                        |         |                         ✓                          |                       ✓                        |  613  |                              7.1                              |
| **3.3.5** | Verify that all pages that require authentication have easy and visible access to logout functionality.                                                                                                                                                                          |    ✓    |                         ✓                          |                       ✓                        |       |                                                               |

### V3.5 Token-based Session Management

Token-based session management includes JWT, OAuth, SAML, and API keys. Of these, API keys are known to be weak and should not be used in new code.

|     #     | Description                                                                                                                                                           |  L1   |  L2   |  L3   |  CWE  | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :-------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---: | :---: | :---: | :---: | :-----------------------------------------------------------: |
| **3.5.1** | Verify the application allows users to revoke OAuth tokens that form trust relationships with linked applications.                                                    |       |   ✓   |   ✓   |  290  |                             7.1.2                             |
| **3.5.2** | Verify the application uses session tokens rather than static API secrets and keys, except with legacy implementations.                                               |       |   ✓   |   ✓   |  798  |                                                               |
| **3.5.3** | Verify that stateless session tokens make use of digital signatures to protect against tampering.                                                                     |   ✓   |   ✓   |   ✓   |  345  |                                                               |
| **3.5.4** | Verify expiration of JWTs is checked in the backend service.                                                                                                          |   ✓   |   ✓   |   ✓   |  613  |                                                               |
| **3.5.5** | Verify that integrity algorithm validation is being done by the backend service for the JWTs and that only valid algorithm types are enforced by the backend service. |   ✓   |   ✓   |   ✓   |  347  |                                                               |
| **3.5.6** | Verify proper validation of the JWT payload claims are done by the backend service including the issuer, subject, and audience.                                       |   ✓   |   ✓   |   ✓   |  287  |                                                               |

---

## OWASP JWT Cheatsheet

> Reference: https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md


### "None" Hashing Algorithm

**Symptom**

This attack, described here occurs when an attacker alters the token and changes the hashing algorithm to indicate, through, the none keyword, that the integrity of the token has already been verified.
As explained in the link above some libraries treated tokens signed with the none algorithm as a valid token with a verified signature, so an attacker can alter the token claims and token will be trusted by the application.

**How to Prevent**

First, use a JWT library that is not exposed to this vulnerability.
Last, during token validation, explicitly request that the expected algorithm was used.

### Token Sidejacking

**Symptom**

This attack occurs when a token has been intercepted/stolen by an attacker and they use it to gain access to the system using targeted user identity.

**How to Prevent**

A way to prevent it is to add a "user context" in the token. A user context will be composed of the following information:

- A random string that will be generated during the authentication phase. It will be sent to the client as an hardened cookie (flags: HttpOnly + Secure + SameSite + cookie prefixes).
- A SHA256 hash of the random string will be stored in the token (instead of the raw value) in order to prevent any XSS issues allowing the attacker to read the random string value and setting the expected cookie.

IP addresses should not be used because there are some legitimate situations in which the IP address can change during the same session.
For example, when an user accesses an application through their mobile device and the mobile operator changes during the exchange, then the IP address may (often) change.
Moreover, using the IP address can potentially cause issues with European GDPR compliance.

During token validation, if the received token does not contain the right context (for example, if it has been replayed), then it must be rejected.

```js
app.post("/api/actions/signup", async (req, res) => {
    try {
        const { email, password } = req.body.input.params

        // Insert a new user record in the database, hashing the plaintext password
        // and configuring a refresh token to be used for re-authing
        const refresh_token = uuidv4()
        const user = await insertUser({
            email,
            password: await hashPassword(password),
            refresh_token,
            // 1 hour, UTC time in ISO format
            refresh_token_expires_at: new Date(Date.now() + 1000 * 60 * 60 * 1).toISOString(),
        })

        // Generate a random string that will constitute the fingerprint for this user
        // Token Sidejacking: "A random string that will be generated during the authentication phase."
        const fingerprint = crypto.randomBytes(50).toString("hex")

        // Add the fingerprint in a hardened cookie to prevent Token Sidejacking
        // https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking
        res.setHeader(
            "Set-Cookie",
            serialize(FINGERPRINT_COOKIE_NAME, fingerprint, {
                path: "/",
                maxAge: MAX_AGE,
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
            })
        )

        // Create JWT claims payload, including a hashed version of the 
        // fingerprint for the client to send back when asking for a token refresh
        const payload = {
            "https://hasura.io/jwt/claims": {
                "X-Hasura-Allowed-Roles": ["user"],
                "X-Hasura-Default-Role": "user",
                "X-Hasura-User-Id": String(user.id),
                // Token Sidejacking:
                // "A SHA256 hash of the random string will be stored in the token
                // (instead of the raw value) in order to prevent any XSS issues allowing the attacker
                // to read the random string value and setting the expected cookie."
                "X-User-Hashed-Fingerprint": sha256(fingerprint),
            },
        }

        // Sign the token, using HMAC SHA256 and give it a short duration
        // (Silent refresh will be responsible for repeated re-authing)
        const token = jwt.sign(payload, JWT_SECRET, {
            algorithm: "HS256",
            expiresIn: "5m",
        })

        // Return the JWT token and refresh token to the client
        return res.json({ jwt: token, refreshToken: user.refresh_token })
    } catch (error) {
        console.log("/api/actions/signup error", error)
        return res.status(400).json({ message: "Error signing up" })
    }
})

app.post("/api/actions/login", async (req, res) => {
    try {
        const { email, password } = req.body.input.params

        // Try to find a user with the given email
        const user = await findUser({ email: { _eq: email } })
        if (!user) return res.status(400).json({ message: "User not found" })

        // Check plaintext password against hashed password in database
        const validPassword = await checkPassword(password, user.password)
        if (!validPassword) return res.status(400).json({ message: "Invalid credentials" })

        // At this point, we have a valid user record and a valid password
        // Update user refresh token and refresh token expiration
        const refresh_token = uuidv4()
        await updateUserRefreshToken({
            id: user.id,
            refresh_token,
            // 1 hour, UTC time in ISO format
            refresh_token_expires_at: new Date(Date.now() + 1000 * 60 * 60 * 1).toISOString(),
        })

        // Generate a random string that will constitute the fingerprint for this user
        // Token Sidejacking: "A random string that will be generated during the authentication phase."
        const fingerprint = crypto.randomBytes(50).toString("hex")

        // Add the fingerprint in a hardened cookie to prevent Token Sidejacking
        // https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking
        res.setHeader(
            "Set-Cookie",
            serialize(FINGERPRINT_COOKIE_NAME, fingerprint, {
                path: "/",
                maxAge: MAX_AGE,
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
            })
        )

        // Create JWT claims payload, including a hashed version of the 
        // fingerprint for the client to send back when asking for a token refresh
        const payload = {
            "https://hasura.io/jwt/claims": {
                "X-Hasura-Allowed-Roles": ["user"],
                "X-Hasura-Default-Role": "user",
                "X-Hasura-User-Id": String(user.id),
                // Token Sidejacking:
                // "A SHA256 hash of the random string will be stored in the token
                // (instead of the raw value) in order to prevent any XSS issues allowing the attacker
                // to read the random string value and setting the expected cookie."
                "X-User-Hashed-Fingerprint": sha256(fingerprint),
            },
        }

        // Sign the token, using HMAC SHA256 and give it a short duration
        // (Silent refresh will be responsible for repeated re-authing)
        const token = jwt.sign(payload, JWT_SECRET, {
            algorithm: "HS256",
            expiresIn: "5m",
        })

        // Return the JWT token and refresh token to the client
        return res.json({ jwt: token, refreshToken: user.refresh_token })
    } catch (error) {
        console.log("/api/actions/login error", error)
        return res.status(400).json({ message: "Error logging in" })
    }
})


app.post("/api/actions/refresh-jwt", async (req, res) => {
    try {
        const { refreshToken, fingerprintHash } = req.body.input

        // First, check for the existence of the fingerprint HttpOnly cookie
        const fingerprintCookie = req.cookies[FINGERPRINT_COOKIE_NAME]
        if (!fingerprintCookie) return res.status(400).json({ message: "Unable to refresh JWT token" })

        // Compute a SHA256 hash of the received fingerprint in cookie in order to compare
        // it to the fingerprint hash stored in the token
        const fingerprintCookieHash = sha256(fingerprintCookie)

        // If the fingerprints don't match, the refresh is not authorized and is potentially malicious
        if (fingerprintHash != fingerprintCookieHash) {
            return res.status(400).json({ message: "Unable to refresh JWT token" })
        }

        // If the fingerprints do match, then continue to look the user up via their refresh token
        const user = await findUser({ refresh_token: { _eq: refreshToken } })
        if (!user) return res.status(400).json({ message: "User not found" })

        // Update user refresh token and refresh token expiration
        await updateUserRefreshToken({
            id: user.id,
            refresh_token: uuidv4(),
            refresh_token_expires_at: new Date(Date.now() + 1000 * 60 * 60 * 1).toISOString(),
        })


        // Sign and return new JWT
        const payload = {
            "https://hasura.io/jwt/claims": {
                "X-Hasura-Allowed-Roles": ["user"],
                "X-Hasura-Default-Role": "user",
                "X-Hasura-User-Id": String(user.id),
                "X-User-Hashed-Fingerprint": sha256(fingerprint),
            },
        }

        const token = jwt.sign(payload, JWT_SECRET, {
            algorithm: "HS256",
            expiresIn: "5m",
        })

        return res.json({ jwt: token })
    } catch (error) {
        console.log("/api/actions/refresh-jwt error", error)
        return res.status(400).json({ message: "Error issuing jwt token refresh" })
    }
})
```


### No Built-In Token Revocation by the User

### Token Information Disclosure

### Token Storage on Client Side

### Weak Token Secret

