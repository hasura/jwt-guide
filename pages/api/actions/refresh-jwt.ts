import nc from "next-connect"
import { uuidv4 } from "../../../lib/auth"
import { findUser, updateUserRefreshToken } from "../../../lib/user"
import { generateHasuraJWT, sha256 } from "../../../lib/jwt"
import { NextApiRequest, NextApiResponse } from "next"
import { FINGERPRINT_COOKIE_NAME } from "../../../lib/setFingerprintCookieAndSignJwt"

export const config = {
    api: {
        bodyParser: true,
    },
}

export default nc<NextApiRequest, NextApiResponse>().post(async (req, res) => {
    try {
        console.log("/api/actions/refresh-token endpoint hit")
        console.log(req.body.input)
        const { refreshToken, fingerprintHash } = req.body.input

        const fingerprintCookie = req.cookies[FINGERPRINT_COOKIE_NAME]
        console.log({ fingerprintCookie })
        if (!fingerprintCookie) return res.status(400).json({ message: "Unable to refresh JWT token" })

        // Compute a SHA256 hash of the received fingerprint in cookie in order to compare
        // it to the fingerprint hash stored in the token
        const fingerprintCookieHash = sha256(fingerprintCookie)
        console.log({ fingerprintCookie, fingerprintCookieHash, fingerprintHash })

        if (fingerprintHash != fingerprintCookieHash) {
            return res.status(400).json({ message: "Unable to refresh JWT token" })
        }

        const user = await findUser({ refresh_token: { _eq: refreshToken } })
        if (!user) return res.status(400).json({ message: "User not found" })

        // Update user refresh token and refresh token expiration
        await updateUserRefreshToken({
            id: user.id,
            refresh_token: uuidv4(),
            refresh_token_expires_at: new Date(Date.now() + 1000 * 60 * 60 * 1).toISOString(),
        })

        const jwt = generateHasuraJWT({
            expiresIn: "5m",
            allowedRoles: ["user"],
            defaultRole: "user",
            otherClaims: {
                "X-Hasura-User-Id": String(user.id),
            },
        })

        return res.json({ jwt })
    } catch (error) {
        console.log("/api/actions/refresh-token endpoint error", error)
        return res.status(400).json({ message: "Error issuing jwt token refresh" })
    }
})
