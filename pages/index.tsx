import { useEffect } from "react"
import { useRouter } from "next/router"
import Link from "next/link"
import { gql, useQuery } from "@apollo/client"

const ViewerQuery = gql`
    query {
        user {
            id
            email
        }
    }
`

const Index = () => {
    const router = useRouter()
    const { data, loading, error } = useQuery(ViewerQuery)
    const viewer = data?.user?.[0]
    const shouldRedirect = !(loading || error || viewer)

    useEffect(() => {
        if (shouldRedirect) {
            router.push("/signin")
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [shouldRedirect])

    if (error) {
        return <p>{error.message}</p>
    }

    if (viewer) {
        return (
            <div>
                <p>You are signed in as {viewer?.email}</p>
                <p>
                    Go to
                    <Link href="/about">
                        <a> about </a>
                    </Link>
                    page.
                </p>
                <p>
                    Or
                    <Link href="/signout">
                        <a> signout </a>
                    </Link>
                </p>
            </div>
        )
    }

    return <p>Loading...</p>
}

export default Index
