import nc from "next-connect"
import { NextApiRequest, NextApiResponse } from "next"
import { serialize } from "cookie"
import { FINGERPRINT_COOKIE_NAME } from "../../../lib/setFingerprintCookieAndSignJwt"

export const config = {
    api: {
        bodyParser: true,
    },
}

export default nc<NextApiRequest, NextApiResponse>().post(async (req, res) => {
    try {
        console.log("/api/actions/signout endpoint hit")
        // Clear fingerprint cookie
        res.setHeader(
            "Set-Cookie",
            serialize(FINGERPRINT_COOKIE_NAME, "", {
                maxAge: -1,
                path: "/",
            })
        )
        return res.json({ ok: true })
    } catch (error) {
        console.log("/api/actions/signout endpoint error", error)
        return res.status(400).json({ message: "Error signing out" })
    }
})
