import { useMemo } from "react"
import { ApolloClient, InMemoryCache, HttpLink, ApolloLink, Operation } from "@apollo/client"
import { WebSocketLink } from "@apollo/client/link/ws"

import { TokenRefreshLink } from "apollo-link-token-refresh"
import merge from "deepmerge"

import decodeJWT from "jwt-decode"
import type { JwtPayload } from "jwt-decode"
import { getJwtToken, getRefreshToken, setJwtToken } from "./auth"
import { getMainDefinition } from "@apollo/client/utilities"

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
        // credentials: "include" is REQUIRED for cookies to work
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

    const tokenRefreshLink = new TokenRefreshLink({
        // Indicates the current state of access token expiration
        // If token not yet expired or user doesn't have a token (guest) true should be returned
        isTokenValidOrUndefined: () => {
            console.log("isTokenValidOrUndefined")
            const token = getJwtToken()

            // If there is no token, the user is not logged in
            // We return true here, because there is no need to refresh the token
            if (!token) return true

            // Otherwise, we check if the token is expired
            const claims: JwtPayload = decodeJWT(token)
            const expirationTimeInSeconds = claims.exp * 1000
            const now = new Date()
            const isValid = expirationTimeInSeconds >= now.getTime()

            // Return true if the token is still valid, otherwise false and trigger a token refresh
            return isValid
        },
        fetchAccessToken: async () => {
            const jwt = decodeJWT(getJwtToken())
            console.log("fetchAccessToken jwt:", jwt)

            const refreshToken = getRefreshToken()
            const fingerprintHash = jwt?.["https://hasura.io/jwt/claims"]?.["X-User-Fingerprint"]

            const request = await fetch(process.env["NEXT_PUBLIC_HASURA_ENDPOINT"], {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    query: `
                      query RefreshJwtToken($refreshToken: String!, $fingerprintHash: String!) {
                        refreshJwtToken(refreshToken: $refreshToken, fingerprintHash: $fingerprintHash) {
                          jwt
                        }
                      }
                    `,
                    variables: {
                        refreshToken,
                        fingerprintHash,
                    },
                }),
            })

            const result = await request.json()
            return result
        },
        handleFetch: (accessToken) => {
            const claims = decodeJWT(accessToken)
            console.log("handleFetch", { accessToken, claims })
            setJwtToken(accessToken)
        },
        handleResponse: (operation, accessTokenField) => (response) => {
            // here you can parse response, handle errors, prepare returned token to
            // further operations
            // returned object should be like this:
            // {
            //    access_token: 'token string here'
            // }
            console.log("handleResponse", { operation, accessTokenField, response })
            return { access_token: response.refreshToken.jwt }
        },
        handleError: (err) => {
            console.warn("Your refresh token is invalid. Try to reauthenticate.")
            console.error(err)
            // Remove invalid tokens
            localStorage.removeItem("jwt")
            localStorage.removeItem("refreshToken")
        },
    })

    // Only use token refresh link on the client
    if (typeof window !== "undefined") {
        return ApolloLink.from([
            tokenRefreshLink,
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
