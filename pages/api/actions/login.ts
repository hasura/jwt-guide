import nc from "next-connect"
import { checkPassword, findUser, updateUserRefreshToken } from "../../../lib/user"
import { NextApiRequest, NextApiResponse } from "next"
import crypto from "crypto"
import { setFingerprintCookieAndSignJwt } from "../../../lib/setFingerprintCookieAndSignJwt"
import { uuidv4 } from "../../../lib/auth"

export const config = {
    api: {
        bodyParser: true,
    },
}

export default nc<NextApiRequest, NextApiResponse>().post(async (req, res) => {
    try {
        console.log("/api/actions/login endpoint hit")

        const { email, password } = req.body.input.params
        console.log("finding user with email", email)

        const user = await findUser({ email: { _eq: email } })
        if (!user) return res.status(400).json({ message: "User not found" })
        console.log("found user", user)

        const validPassword = await checkPassword(password, user.password)
        if (!validPassword) return res.status(400).json({ message: "Invalid credentials" })

        // Update user refresh token and refresh token expiration
        const refresh_token = uuidv4()
        console.log("updating user refresh token", refresh_token)
        await updateUserRefreshToken({
            id: user.id,
            refresh_token,
            // 1 hour, UTC time in ISO format
            refresh_token_expires_at: new Date(Date.now() + 1000 * 60 * 60 * 1).toISOString(),
        })

        // //Generate a random string that will constitute the fingerprint for this user
        const fingerprint = crypto.randomBytes(50).toString("hex")

        // Add the fingerprint in a hardened cookie to prevent Token Sidejacking
        // https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking
        const jwt = setFingerprintCookieAndSignJwt(fingerprint, res, user)

        console.log("returning jwt", jwt)
        return res.json({ jwt, refreshToken: user.refresh_token })
    } catch (error) {
        console.log("/api/actions/login endpoint error", error)
        return res.status(400).json({ message: "Error logging in" })
    }
})
