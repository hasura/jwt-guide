import { generateHasuraJWT, sha256 } from "./jwt"
import { serialize } from "cookie"
import { NextApiResponse } from "next"

export const FINGERPRINT_COOKIE_NAME = "__User-Fgp"
export const FINGERPRINT_COOKIE_MAX_AGE = 60 * 60 * 8 // 8 hours

export function setFingerprintCookieAndSignJwt(fingerprint: string, res: NextApiResponse, user: any) {
    res.setHeader(
        "Set-Cookie",
        serialize(FINGERPRINT_COOKIE_NAME, fingerprint, {
            path: "/",
            maxAge: FINGERPRINT_COOKIE_MAX_AGE,
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
        })
    )

    return generateHasuraJWT({
        allowedRoles: ["user"],
        defaultRole: "user",
        expiresIn: "5m",
        otherClaims: {
            "X-Hasura-User-Id": String(user.id),
            "X-User-Fingerprint": sha256(fingerprint),
        },
    })
}
