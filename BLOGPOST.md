The Ultimate Guide to handling JWTs on frontend clients (GraphQL)

JWTs (JSON Web Token, pronounced 'jot') are becoming a popular way of handling auth.
This post aims to demystify what a JWT is, discuss its pros/cons and cover best practices in implementing JWT on the client-side, keeping security in mind.
Although, we’ve worked on the examples with a GraphQL clients, but the concepts apply to any frontend client.

> Note: This guide originally published on Septermber 9th, 2019. Last updated on December 28, 2021.

Changelog:
- (12/28/2021) Recommendation to store token in Cookie changed to `sessionStorage`, per OWASP JWT guidelines to address `Issue: Token Storage on Client Side` [0]
- (12/28/2021) Adopted OWASP Application Security Verification Standard  v5 [6] L1-L2 guidelines 
  - Of note: Chapters 3 (`Session Management`) and 8 (`Data Protection`)
- (12/28/2021) Sample application repo code updated [1]
    - Update from Next.js 9 -> 12, update `@apollo` libraries to `v3.x`
    - Password hashing algorithm changed from `bcrypt` to native Node.js `crypto.scrypt` per OWASP guidelines [2] and to reduce number of external dependencies
    - Authentication on frontend and backend modified to make use of a user fingerprint in addition to a token, per OWASP guidelines on preventing `Token Sidejacking` [3]
    - Example usage of `TokenRefreshLink` [4] to manage silent refresh workflow added
    - Server endpoints integrated through Hasura Actions [5] rather than directly invoking from client
    - Adopt recommended use of `crypto.timingSafeEqual()` to prevent timing attacks 

[0]: https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md#symptom-4
[1]: https://github.com/hasura/jwt-guide
[2]: https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Password_Storage_Cheat_Sheet.md#scrypt
[3]: https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md#token-sidejacking
[4]: https://github.com/newsiberian/apollo-link-token-refresh
[5]: https://hasura.io/docs/latest/graphql/core/actions/index.html
[6]: https://owasp.org/www-project-application-security-verification-standard/

---

- [Introduction: What is a JWT?](#introduction-what-is-a-jwt)
  - [Security Considerations](#security-considerations)
  - [JWT Structure](#jwt-structure)
- [Basics: Login](#basics-login)
- [Basics: Client setup](#basics-client-setup)
- [Basics: Logout](#basics-logout)
- [Silent refresh](#silent-refresh)
- [Persisting sessions](#persisting-sessions)
- [Force logout, aka Logout of all sessions/devices](#force-logout-aka-logout-of-all-sessionsdevices)
- [Server side rendering (SSR)](#server-side-rendering-ssr)
- [How does the SSR server know if the user is logged in?](#how-does-the-ssr-server-know-if-the-user-is-logged-in)
- [Code from this blogpost (finished application)](#code-from-this-blogpost-finished-application)
- [Try it out!](#try-it-out)
- [References](#references)
- [Summary](#summary)

# Introduction: What is a JWT?

For a detailed, technical description of JWTs refer to this article.

For the purposes of auth, a JWT is a token that is issued by the server. The token has a JSON payload that contains information specific to the user. This token can be used by clients when talking to APIs (by sending it along as an HTTP header) so that the APIs can identify the user represented by the token, and take user specific action.

## Security Considerations

**But can’t a client just create a random JSON payload an impersonate a user?**

Good question! That’s why a JWT also contains a signature. This signature is created by the server that issued the token (let’s say your login endpoint) and any other server that receives this token can independently verify the signature to ensure that the JSON payload was not tampered with, and has information that was issued by a legitimate source.

**But if I have a valid and signed JWT and someone steals it from the client, can’t they use my JWT forever?**

Yes! If a JWT is stolen, then the thief can can keep using the JWT. An API that accepts JWTs does an independent verification without depending on the JWT source so the API server has no way of knowing if this was a stolen token! This is why JWTs have an expiry value. And these values are kept short. Common practice is to keep it around 15 minutes, so that any leaked JWTs will cease to be valid fairly quickly. But also, make sure that JWTs don’t get leaked.

> These 2 facts result in almost all the peculiarities about handling JWTs! The fact that JWTs shouldn’t get stolen and that they need to have short expiry times in case they do get stolen.

That’s why it’s also really important not to store JWT on the client, say via cookies or localstorage. Doing so you make your app vulnerable to CSRF & XSS attacks, by malicious forms or scripts to use or steal your token lying around in cookies or localstorage.

## JWT Structure

So does a JWT have a specific kind of structure? What does it look like?

A JWT looks something like this, when it's serialized:

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`

If you decode that base64, you'll get JSON in 3 important parts:  **header**, **payload** and **signature**.

![JWT Claims Example from JWT.io](https://hasura.io/blog/content/images/2019/08/Group.png)

The 3 parts of a JWT (based on image taken from jwt.io)
The serialized form is in the following format:

`[ base64UrlEncode(header) ] . [ base64UrlEncode(payload) ] . [ signature ]`

> A JWT is not encrypted. It is based64 encoded and signed. So anyone can decode the token and use its data. A JWT's signature is used to verify that it is in fact from a legitimate source.

Here is the diagram of how a JWT is issued (`/login`) and then used to make an API call to another service (`/api`) in a nutshell:

![JWT End-to-End Workflow](https://hasura.io/blog/content/images/2019/08/Screen-Shot-2019-08-29-at-12.54.53.png)
A workflow of how a JWT is issued and then used

**Ugh! This seems complicated. Why shouldn’t I stick to good old session tokens?**

This is a painful discussion on the Internet. Our short (and opinionated answer) is that backend developers like using JWTs because a) microservices b) not needing a centralized token database.

In a microservices setup, each microservice can independently verify that a token received from a client is valid. The microservice can further decode the token and extract relevant information without needing to have access to a centralized token database.

This is why API developers like JWTs, and we (on the client-side) need to figure out how to use it. However, if you can get away with a session token issued by your favourite monolithic framework, you’re totally good to go and probably don’t need JWTs!

---

# Basics: Login

Now that we have a basic understanding what a JWT is, let's create a simple login flow and extract the JWT. This is what we want to achieve:

![](https://hasura.io/blog/content/images/2019/08/Screen-Shot-2019-08-27-at-8.21.35.png)
A login flow for getting a JWT

**So how do we start?**

The login process doesn’t really change from what you'd usually do. For example, here’s a login form that submits a username/password to an auth endpoint and grabs the JWT token from the response. This could be login with an external provider, an OAuth or OAuth2 step. It really doesn't matter, as long as the client finally gets a JWT token in the response of the final login success step.

First, we'll build a simple login form to send the username and password to our login server. The server will issue JWT token and we will store it in memory. In this tutorial we won’t focus on auth server backend, but you're welcome to check it out in example repo for this blogpost.

This is what the `handleSubmit` handler for a login button might look like:

```js
async function handleSubmit () {
  //...
  // Make the login API call
  const response = await fetch(`/auth/login`, {
    method: 'POST',
    body: JSON.stringify({ username, password })
  })
  //...
  // Extract the JWT from the response
  const { jwt_token } = await response.json()
  //...
  // Do something the token in the login method
  await login({ jwt_token })
}
```

The login API returns a **token** and then we pass this token to a `login` function from `/utils/auth` where we can decide what to do with the token once we have it.

```js
import { login } from '../utils/auth'
await login({ jwt_token })
```

**So we’ve got the token, now where do we store this token?**

We need to save our JWT token somewhere, so that we can forward it to our API as a header. You might be tempted to persist it in localstorage; don’t do it! This is prone to XSS attacks.

**What about saving it in a cookie?**

Creating cookies on the client to save the JWT will also be prone to XSS. If it can be read on the client from Javascript outside of your app - it can be stolen. You might think an HttpOnly cookie (created by the server instead of the client) will help, but cookies are vulnerable to CSRF attacks. It is important to note that HttpOnly and sensible CORS policies cannot prevent CSRF form-submit attacks and using cookies require a proper CSRF mitigation strategy.

Note that the new SameSite cookie spec which is getting increased support in most browsers will make Cookie based approaches safe from CSRF attacks. It might not be a solution if your Auth and API servers are hosted on different domains, but it should work really well otherwise!

**Where do we save it then?**

The [OWASP JWT Cheatsheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md) and [OWASP ASVS (Application Security Verification Standard)](https://github.com/OWASP/ASVS) prescribe guidelines for handling and storing tokens.

The sections that are relevant to this are the `Token Storage on Client Side` and `Token Sidejacking` issues in the JWT Cheatsheet, and chapters 3 (`Session Management`) and 8 (`Data Protection`) of ASVS.

From the Cheatsheet, `Issue: Token Storage on the Client Side`:

_"This occurs when an application stores the token in a manner exhibiting the following behavior:"_

- Automatically sent by the browser (Cookie storage).
- Retrieved even if the browser is restarted (Use of browser localStorage container).
- Retrieved in case of XSS issue (Cookie accessible to JavaScript code or Token stored in browser local/session storage).

_"How to Prevent:"_

- Store the token using the browser `sessionStorage` container.
- Add it as a Bearer HTTP `Authentication` header with JavaScript when calling services.
- Add `fingerprint` information to the token.

By storing the token in browser sessionStorage container it exposes the token to being stolen through a XSS attack. However, fingerprints added to the token prevent reuse of the stolen token by the attacker on their machine. To close a maximum of exploitation surfaces for an attacker, add a browser `Content Security Policy` to harden the execution context.

Where a `fingerprint` is the implementation of the following guidelines from the `Token Sidejacking` issue:

_"Symptom:"_

This attack occurs when a token has been intercepted/stolen by an attacker and they use it to gain access to the system using targeted user identity.

_*How to Prevent:*_

A way to prevent it is to add a `"user context"` in the token. A user context will be composed of the following information:

- A random string that will be generated during the authentication phase. It will be sent to the client as an hardened cookie (flags: `HttpOnly` + `Secure` + `SameSite` + cookie prefixes).
- A SHA256 hash of the random string will be stored in the token (instead of the raw value) in order to prevent any XSS issues allowing the attacker to read the random string value and setting the expected cookie.

IP addresses should not be used because there are some legitimate situations in which the IP address can change during the same session. For example, when an user accesses an application through their mobile device and the mobile operator changes during the exchange, then the IP address may (often) change. Moreover, using the IP address can potentially cause issues with European GDPR compliance.

During token validation, if the received token does not contain the right context (for example, if it has been replayed), then it must be rejected.

---

An implementation of this on the clint side may look like:

```js
// Short duration JWT token (5-10 min)
export function getJwtToken() {
    return sessionStorage.getItem("jwt")
}

export function setJwtToken(token) {
    sessionStorage.setItem("jwt", token)
}

// Longer duration refresh token (30-60 min)
export function getRefreshToken() {
    return sessionStorage.getItem("refreshToken")
}

export function setRefreshToken(token) {
    sessionStorage.setItem("refreshToken", token)
}

function handleLogin({ email, password }) {
  // Call login method in API
  // The server handler is responsible for setting user fingerprint cookie during this as well
  const { jwtToken, refreshToken } = await login({ email, password })
  setJwtToken(jwtToken)
  setRefreshToken(refreshToken)

  // If you like, you may redirect the user now
  Router.push("/some-url")
}
```

Yes, the token will be nullified when the user switches between tabs, but we will deal with that later.

**Ok! Now that we have the token what can we do with it?**

- Using in our API client to pass it as a header to every API call
- Check if a user is logged in by seeing if the JWT variable is set.
- Optionally, we can even decode the JWT on the client to access data in the payload. Let's say we need the user-id or the username on the client, which we can extract from the JWT.

**How do we check if our user is logged in?**

We check in our if the token variable is set and if it isn't - redirect to login page.

```js
const jwtToken = getJwtToken();
if (!jwtToken) {
  Router.push('/login')
}
```

---

# Basics: Client setup

Now it’s time to set up our GraphQL client. The idea is to get the token from the variable we set, and if it’s there, we pass it to our GraphQL client.

![](./https://hasura.io/blog/content/images/2019/08/Screen-Shot-2019-08-30-at-9.21.00.png)
Using the JWT in a GraphQL client

Assuming your GraphQL API accepts a JWT auth token as an `Authorization` header, all you need to do is setup your client to set an HTTP header by using the JWT token from the variable.

Here's what a setup with the Apollo GraphQL client using an `ApolloLink` middleware.

```js
import { useMemo } from "react"
import { ApolloClient, InMemoryCache, HttpLink, ApolloLink, Operation } from "@apollo/client"
import { getMainDefinition } from "@apollo/client/utilities"
import { WebSocketLink } from "@apollo/client/link/ws"
import merge from "deepmerge"

let apolloClient

function getHeaders() {
    const headers = {} as HeadersInit
    const token = getJwtToken()
    if (token) headers["Authorization"] = `Bearer ${token}`
    return headers
}

function operationIsSubscription(operation: Operation): boolean {
    const definition = getMainDefinition(operation.query)
    const isSubscription = definition.kind === "OperationDefinition" && definition.operation === "subscription"
    return isSubscription
}

let wsLink
function getOrCreateWebsocketLink() {
    wsLink ??= new WebSocketLink({
        uri: process.env["NEXT_PUBLIC_HASURA_ENDPOINT"].replace("http", "ws").replace("https", "wss"),
        options: {
            reconnect: true,
            timeout: 30000,
            connectionParams: () => {
                return { headers: getHeaders() }
            },
        },
    })
    return wsLink
}

function createLink() {
    const httpLink = new HttpLink({
        uri: process.env["NEXT_PUBLIC_HASURA_ENDPOINT"],
        credentials: "include",
    })

    const authLink = new ApolloLink((operation, forward) => {
        operation.setContext(({ headers = {} }) => ({
            headers: {
                ...headers,
                ...getHeaders(),
            },
        }))
        return forward(operation)
    })

    if (typeof window !== "undefined") {
        return ApolloLink.from([
            authLink,
            // Use "getOrCreateWebsocketLink" to init WS lazily
            // otherwise WS connection will be created + used even if using "query"
            ApolloLink.split(operationIsSubscription, getOrCreateWebsocketLink, httpLink),
        ])
    } else {
        return ApolloLink.from([authLink, httpLink])
    }
}

function createApolloClient() {
    return new ApolloClient({
        ssrMode: typeof window === "undefined",
        link: createLink(),
        cache: new InMemoryCache(),
    })
}

export function initializeApollo(initialState = null) {
    const _apolloClient = apolloClient ?? createApolloClient()

    // If your page has Next.js data fetching methods that use Apollo Client, the initial state
    // get hydrated here
    if (initialState) {
        // Get existing cache, loaded during client side data fetching
        const existingCache = _apolloClient.extract()

        // Merge the existing cache into data passed from getStaticProps/getServerSideProps
        const data = merge(initialState, existingCache)

        // Restore the cache with the merged data
        _apolloClient.cache.restore(data)
    }

    // For SSG and SSR always create a new Apollo Client
    if (typeof window === "undefined") return _apolloClient
    // Create the Apollo Client once in the client
    if (!apolloClient) apolloClient = _apolloClient

    return _apolloClient
}

export function useApollo(initialState) {
    const store = useMemo(() => initializeApollo(initialState), [initialState])
    return store
}
```

As you can see from the code, whenever there is a token, it’s passed as a header to every request.

**But what will happen if there is no token?**

It depends on the flow in your application. Let's say you redirect the user back to the login page:

```js
else {
 Router.push('/login')
}
```

**What happens if a token expires as we're using it?**

Let's say our token is only valid for 15 minutes. In this case we'll probably get an  error from our API denying our request (let's say a `401: Unauthorized` error). Remember that every service that knows how to use a JWT can independently verify it and check whether it has expired or not.

Let’s add error handling to our app to handle this case. We'll write code that will run for every API response and check the error. When we receive the token expired/invalid error from our API, we trigger the logout or the redirect to login workflow.

Here's what the code looks like if we're using the Apollo client:

```js
import { onError } from 'apollo-link-error';

const logoutLink = onError(({ networkError }) => {
    if (networkError.statusCode === 401) logout();
})

if (typeof window !== "undefined") {
    return ApolloLink.from([
        logoutLink,
        authLink,
        ApolloLink.split(operationIsSubscription, getOrCreateWebsocketLink, httpLink),
    ])
} else {
    return ApolloLink.from([
      logoutLink,
      authLink,
      httpLink
    ])
}
```

You may notice that this will result in a fairly sucky user experience. The user will keep getting asked to re-authenticate every time the token expires. This is why apps implement a silent refresh workflow that keeps refreshing the JWT token in the background. More on this in the next sections below!

> As you may know, with Hasura's GraphQL API, you get built-in authorization. [Anon, our engineer, speaks about how to model popular enterprise authorization systems like RBAC, ABAC, AWS IAM and GCP IAM in Hasura. If interested, do check out the webinar recording.](https://hasura.io/events/webinar/authorization-modeling-hasura/?pg=blog&plcmt=body&cta=blog-ctas&tech=)

# Basics: Logout

With JWTs, a "logout" is simply deleting the token on the client side so that it can't be used for subsequent API calls.

![](https://hasura.io/blog/content/images/2019/08/Screen-Shot-2019-08-29-at-14.33.25.png)

**So...is there no `/logout` API call at all?**

A `logout` endpoint is not really required, because any microservice that accepts your JWTs will keep accepting it. If your auth server deletes the JWT, it won't matter because the other services will keep accepting it anyway (since the whole point of JWTs was to not require centralised coordination).

**The token is still valid and can be used. What if I need to ensure that the token cannot be used ever again?**

This is why keeping JWT expiry values to a small value is important. And this is why ensuring that your JWTs don't get stolen is even more important. The token is valid (even after you delete it on the client), but only for short period to reduce the probability of it being used maliciously.

In addition, you can add a deny-listing workflow to your JWTs. In this case, you can have a `/logout` API call and your auth server puts the tokens in a "invalid list". However, all the API services that consume the JWT now need to add an additional step to their JWT verification to check with the centralized "deny-list". This introduces central state again, and brings us back to what we had before using JWTs at all.

![](https://hasura.io/blog/content/images/2019/08/Screen-Shot-2019-08-29-at-14.33.14.png)

**Doesn’t deny-listing negate the benefit of JWT not needing any central storage?**

In a way it does. It’s an optional precaution that you can take if you are worried that your token can get stolen and misused, but it also increases the amount of verification that has to be done. As you can imagine, this had led to much [gnashing of teeth on the internet.](https://stackoverflow.com/questions/21978658/invalidating-json-web-tokens/52407314#52407314)

**What will happen if I am logged in on different tabs?**

One way of solving this is by introducing a global event listener on localstorage. Whenever we update this logout key in localstorage on one tab, the listener will fire on the other tabs and trigger a "logout" too and redirect users to the login screen.

```js
window.addEventListener('storage', this.syncLogout) 

//....

syncLogout (event) {
  if (event.key === 'logout') {
    console.log('logged out from storage!')
    Router.push('/login')
  }
}
```

These are the 2 things we now need to do on logout:

1. Nullify the token
2. Set `logout` item in local storage

```js
async function logout () {
  inMemoryToken = null;
  const url = 'http://localhost:3010/auth/logout'
  const response = await fetch(url, {
    method: 'POST',
    credentials: 'include',
  })
  // to support logging out from all windows
  window.localStorage.setItem('logout', Date.now())
}
```

In that case whenever you log out from one tab, event listener will fire in all other tabs and redirect them to login screen.

**This works across tabs. But how do I "force logout" of all sessions on different devices?!**

We cover this topic in a little more detail in a section later on: Force logout.

# Silent refresh

There are 2 major problems that users of our JWT based app will still face:

1. Given our short expiry times on the JWTs, the user will be logged out every 15 minutes. This would be a fairly terrible experience. Ideally, we'd probably want our user to be logged in for a long time.
2. If a user closes their app and opens it again, they'll need to login again. Their session is not *persisted* because we're not saving the JWT token on the client anywhere.

To solve this problem, most JWT providers, provide a refresh token. A refresh token has 2 properties:

1. It can be used to make an API call (say, `/refresh_token`) to fetch a new JWT token before the previous JWT expires.
2. It can be safely persisted across sessions on the client!

**How does a refresh token work?**

This token is issued as part of authentication process along with the JWT. The auth server should saves this refresh token and associates it to a particular user in its own database, so that it can handle the renewing JWT logic.

On the client, before the previous JWT token expires, we wire up our app to make a `/refresh_token` endpoint and grab a new JWT.

How is a refresh token safely persisted on the client?!

The refresh token is sent by the auth server to the client as an `HttpOnly` cookie and is automatically sent by the browser in a `/refresh_token` API call.

Because client side Javascript can't read or steal an `HttpOnly` cookie, this is a little better at mitigating XSS than persisting it as a normal cookie or in localstorage.

This is safe from [CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)) attacks, because even though a form submit attack can make a `/refresh_token` API call, the attacker cannot get the new JWT token value that is returned.

To recap, this is how we're thinking about what would be the best way of persisting a JWT based session:

```
Persisting JWT token in localstorage (prone to XSS) <
Persisting JWT token in an HttpOnly cookie (prone to CSRF, a little bit better for XSS) < Persisting refresh token in an HttpOnly cookie (safe from CSRF, a little bit better for XSS).
```

Note that while this method is not resilient to serious XSS attacks, coupled with the [usual XSS mitigation techniques](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#xss-prevention-rules), an `HttpOnly` cookie is a [recommended way](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#bonus-rule-1-use-httponly-cookie-flag) of persisting session related information. But by persisting our session indirectly via a refresh token, we prevent a direct CSRF vulnerability we would have had with a JWT token.

**So what does the new "login" process look like?**

Nothing much changes, except that a refresh token gets sent along with the JWT. Let's take a look a diagram of login process again, but now with `refresh_token` functionality:

![Login with refresh token](https://hasura.io/blog/content/images/2019/09/Screen-Shot-2019-09-06-at-11.46.17.png)

1. The user logs in with a login API call.
2. Server generates JWT Token and `refresh_token`
3. Server sets a `HttpOnly` cookie with `refresh_token`. `jwt_token` and `jwt_token_expiry` are returned back to the client as a JSON payload.
4. The `jwt_token` is stored in memory.
5. A countdown to a future silent refresh is started based on `jwt_token_expiry`

**And now, what does the silent refresh look like?**

![Silent refresh workflow](https://hasura.io/blog/content/images/2019/09/Screen-Shot-2019-09-06-at-11.46.10.png)
Silent refresh workflow

Here's what happens:

1. Call `/refresh_token` endpoint
2. Server will read `HttpOnly` cookie and if it finds a valid `refresh_token`, then...
3. ...the server returns a new `jwt_token` and `jwt_token_expiry` to the client and also sets a new *refresh token* cookie via `Set-Cookie` header.

---

# Persisting sessions

Now that we can make sure that our users don't keep getting logged out, let's turn our attention to the second problem of persisting sessions.

You'll notice that if users close your app and open it again (lets say by closing the browser tab and re-opening it), they'll be asked to login again.

Apps usually ask their users if they want to "stay logged in" across sessions, or by default, keep their users logged in. This is what we'd like to implement as well.

Currently, we can't do this because the JWT is only stored in memory and is not persisted. To recap, head to this section above to see why we can't store JWTs in cookies or in localstorage directly.

**So how do we persist sessions securely then?**

Refresh tokens! We were able to persist refresh tokens securely and use them for silent refresh (aka renewing our short expiry JWT tokens without asking users to login again). And we can also use them to fetch a new JWT token for a new session! Check out the previous section discussing how refresh tokens are persisted.

Let's say that the user logged out of their current session by closing their browser tab. Now that the user visits the app again, let's see what the flow looks like:

![JWT Silent Refresh Flow Diagram](https://hasura.io/blog/content/images/2019/09/Screen-Shot-2019-09-06-at-11.46.03.png)

1. If we see that we don't have a JWT in memory, then we trigger the silent refresh workflow
2. If the refresh token is still valid (or hasn't been revoked), then we get a new JWT and we're good to go!

**Possible error case:**

In case our refresh token expires (say the user comes back to the app after a really long time), or gets revoked (because of a "force logout", say) the client will get 401 error for an unauthorized `refresh_token`. Another case might just be that we don’t have any `refresh_token` in the first place, in which case we'll also get an error from our `/refresh_token endpoint` and we will redirect the user to the login screen.

Here's some sample code showing how we would deal with this error handling using a `logoutLink`

```js
const logoutLink = onError(({ networkError }) => {
 if (networkError.statusCode === 401) logout();
})
```

---

# Force logout, aka Logout of all sessions/devices

Now that are users are logged in forever and stay logged in across sessions, there's a new problem that we need to worry about: Force logout or, logging out of all sessions and devices.

The refresh token implementations from the sections above, show us that we can persist sessions and stay logged in.

In this case, a simple implementation of "force logout" is asking the auth server to invalidate all refresh tokens associated for a particular user.

This is primarily an implementation on the auth server backend, and doesn't need any special handling on the client. Apart from a "Force Logout" button on your app perhaps :)

---

# Server side rendering (SSR)

In server side rendering there are additional complexities involved when dealing with JWT tokens.

This is what we want:

1. The browser makes a request to a app URL
2. The SSR server renders the page based on the user's identity
3. The user gets the rendered page and then continues using the app as an SPA (single page app)

# How does the SSR server know if the user is logged in?

The browser needs to send some information about the current user's identity to the SSR server. The only way to do this is via a cookie.

Since we've already implemented refresh token workflows via cookies, when we make a request to the SSR server, we need to make sure that the refresh-token is also sent along.

> **Note:** For SSR on authenticated pages, it is vital that that the domain of the auth API (and hence the domain of the `refresh_token` cookie) is the same as the domain of the SSR server. Otherwise, our cookies won't be sent to the SSR server!

![](https://hasura.io/blog/content/images/2019/09/Screen-Shot-2019-09-06-at-11.43.22.png)

This is what the SSR server does:

1. Upon receiving a request to render a particular page, the SSR server captures the refresh_token cookie.
2. The SSR server uses the refresh_token cookie to get a new JWT for the user
3. The SSR server uses the new JWT token and makes all the authenticated GraphQL requests to fetch the right data

**Can the user continue making authenticated API requests once the SSR page has loaded?**

Nope, not without some additional fiddling around unfortunately!

Once the SSR server returns the rendered HTML, the only identification left on the browser about the user's identity is the old refresh token cookie that has already been used by the SSR server!

If our app code tries to use this refresh token cookie to fetch a new JWT, this request will fail and the user will get logged out.

To solve this, the SSR server after rendering the page needs to send the latest refresh token cookie, so that the browser can use it!

**The entire SSR flow, end to end:**

![](https://hasura.io/blog/content/images/2019/09/Screen-Shot-2019-09-06-at-11.43.32.png)

---

# Code from this blogpost (finished application)

Sample code for this blogpost with an end to end working app, with SSR capabilities is available here.

The repository also contains the sample auth backend code (based on the awesome https://github.com/elitan/hasura-backend-plus).

---

# Try it out!

Set up a free GraphQL backend with [Hasura Cloud](https://cloud.hasura.io/?pg=blog&plcmt=body&cta=blog-ctas&tech=) to try it out for yourself!

Make sure you're on version 1.3 or above and you're good to go.

---

# References
- JWT.io
- OWASP notes on XSS, CSRF and similar things
- The Parts of JWT Security Nobody Talks About | Philippe De Ryck
Lots of other awesome stuff on the web

---

# Summary

Once you've worked through all the sections above, your app should now have all the capabilities of a modern app, using a JWT and should be secure from the common major security gotchas that JWT implementations have!

Let us know on [twitter](https://twitter.com/intent/tweet?text=Hey%2C%20%40VladimirNovick%20and%20%40HasuraHQ%2C%20regarding%20the%20blog%20post%20https%3A%2F%2Fbit.ly%2F2kAoaWe%2C%20) or in the comments below if you have any questions, suggestions or feedback!
