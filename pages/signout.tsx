import { useEffect } from "react"
import { useRouter } from "next/router"
import { gql, useMutation, useApolloClient } from "@apollo/client"
import { setJwtToken, setRefreshToken } from "../lib/auth"

const SignOutMutation = gql`
    mutation SignOutMutation {
        signout {
            ok
        }
    }
`

function SignOut() {
    const client = useApolloClient()
    const router = useRouter()
    const [signOut] = useMutation(SignOutMutation)

    useEffect(() => {
        // Clear the JWT and refresh token so that Apollo doesn't try to use them
        setJwtToken("")
        setRefreshToken("")
        // Hit the signout endpoint to clear the fingerprint cookie
        // Tell Apollo to reset the store
        // Finally, redirect the user to the home page
        signOut().then(() => {
            client.resetStore().then(() => {
                router.push("/signin")
            })
        })
    }, [signOut, router, client])

    return <p>Signing out...</p>
}

export default SignOut
