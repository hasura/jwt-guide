import * as jwt from "jsonwebtoken"
import crypto from "crypto"

export function sha256(value: string) {
    return crypto.createHash("sha256").update(value, "utf8").digest("hex")
}

const HASURA_GRAPHQL_JWT_SECRET = {
    type: process.env.HASURA_JWT_SECRET_TYPE || "HS256",
    key: process.env.HASURA_JWT_SECRET_KEY || "this-is-a-generic-HS256-secret-key-and-you-should-really-change-it",
}

interface GenerateJWTParams {
    allowedRoles: string[]
    defaultRole: string
    otherClaims?: Record<string, string>
    expiresIn?: string
}

export function generateHasuraJWT(params: GenerateJWTParams) {
    const payload = {
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": params.allowedRoles,
            "x-hasura-default-role": params.defaultRole,
            ...params.otherClaims,
        },
    }

    return jwt.sign(payload, HASURA_GRAPHQL_JWT_SECRET.key, {
        algorithm: HASURA_GRAPHQL_JWT_SECRET.type as "HS256" | "RS512",
        expiresIn: params.expiresIn || "1h",
    })
}
