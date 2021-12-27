import { useState } from "react"
import { useRouter } from "next/router"
import Link from "next/link"
import { gql, useMutation } from "@apollo/client"
import { getErrorMessage } from "../lib/form"
import Field from "../components/field"
import { setJwtToken, setRefreshToken } from "../lib/auth"

const SignUpMutation = gql`
    mutation SignUpMutation($email: String!, $password: String!) {
        signup(params: { email: $email, password: $password }) {
            jwt
            refreshToken
        }
    }
`

function SignUp() {
    const [signUp] = useMutation(SignUpMutation)
    const [errorMsg, setErrorMsg] = useState()
    const router = useRouter()

    async function handleSubmit(event) {
        event.preventDefault()
        const emailElement = event.currentTarget.elements.email
        const passwordElement = event.currentTarget.elements.password

        try {
            const req = await signUp({
                variables: {
                    email: emailElement.value,
                    password: passwordElement.value,
                },
            })

            console.log("Signup result:", req.data)
            if (req?.data?.signup?.jwt) {
                setJwtToken(req.data.signup.jwt)
                setRefreshToken(req.data.login.refreshToken)
            }
        } catch (error) {
            setErrorMsg(getErrorMessage(error))
        }
    }

    return (
        <>
            <h1>Sign Up</h1>
            <form onSubmit={handleSubmit}>
                {errorMsg && <p>{errorMsg}</p>}
                <Field name="email" type="email" autoComplete="email" required label="Email" />
                <Field name="password" type="password" autoComplete="password" required label="Password" />
                <button type="submit">Sign up</button> or{" "}
                <Link href="/signin">
                    <a>Sign in</a>
                </Link>
            </form>
        </>
    )
}

export default SignUp
