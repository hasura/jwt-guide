import { ApolloProvider } from "@apollo/client"
import { useApollo } from "../lib/apollo-client"

export default function App({ Component, pageProps }) {
    const apolloClient = useApollo(pageProps.initialApolloState)

    // Taken from https://blog.guya.net/2015/06/12/sharing-sessionstorage-between-tabs-for-secure-multi-tab-authentication/
    // This is a secure way to share sessionStorage between tabs.
    if (typeof window !== "undefined") {
        if (!sessionStorage.length) {
            // Ask other tabs for session storage
            console.log("Calling getSessionStorage")
            localStorage.setItem("getSessionStorage", String(Date.now()))
        }

        window.addEventListener("storage", (event) => {
            console.log("storage event", event)
            if (event.key == "getSessionStorage") {
                // Some tab asked for the sessionStorage -> send it
                localStorage.setItem("sessionStorage", JSON.stringify(sessionStorage))
                localStorage.removeItem("sessionStorage")
            } else if (event.key == "sessionStorage" && !sessionStorage.length) {
                // sessionStorage is empty -> fill it
                const data = JSON.parse(event.newValue)
                for (let key in data) {
                    sessionStorage.setItem(key, data[key])
                }
            }
        })
    }

    return (
        <ApolloProvider client={apolloClient}>
            <Component {...pageProps} />
        </ApolloProvider>
    )
}
