import { useState } from "react"
import { useRouter } from "next/router"
import Link from "next/link"
import { gql, useLazyQuery } from "@apollo/client"
import { useMutation, useApolloClient } from "@apollo/client"
import { getErrorMessage } from "../lib/form"
import Field from "../components/field"
import { setJwtToken, setRefreshToken } from "../lib/auth"

const SignInMutation = gql`
    query SignIn($email: String!, $password: String!) {
        login(params: { email: $email, password: $password }) {
            jwt
            refreshToken
        }
    }
`

function SignIn() {
    const client = useApolloClient()
    const [signIn] = useLazyQuery(SignInMutation)
    const [errorMsg, setErrorMsg] = useState()
    const router = useRouter()

    async function handleSubmit(event) {
        event.preventDefault()

        const emailElement = event.currentTarget.elements.email
        const passwordElement = event.currentTarget.elements.password

        try {
            await client.resetStore()
            const { data } = await signIn({
                variables: {
                    email: emailElement.value,
                    password: passwordElement.value,
                },
            })
            if (data?.login != null) {
                setJwtToken(data.login.jwt)
                setRefreshToken(data.login.refreshToken)
                await router.push("/")
            }
        } catch (error) {
            setErrorMsg(getErrorMessage(error))
        }
    }

    return (
        <>
            <h1>Sign In</h1>
            <form onSubmit={handleSubmit}>
                {errorMsg && <p>{errorMsg}</p>}
                <Field name="email" type="email" autoComplete="email" required label="Email" />
                <Field name="password" type="password" autoComplete="password" required label="Password" />
                <button type="submit">Sign in</button> or{" "}
                <Link href="/signup">
                    <a>Sign up</a>
                </Link>
            </form>
        </>
    )
}

export default SignIn
