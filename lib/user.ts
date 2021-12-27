import crypto from "crypto"
import { promisify } from "util"

const scrypt = promisify(crypto.scrypt)

export async function hashPassword(password) {
    const salt = crypto.randomBytes(8).toString("hex")
    const derivedKey = await scrypt(password, salt, 64)
    // @ts-ignore
    return salt + ":" + derivedKey.toString("hex")
}

export async function checkPassword(plaintextPassword, hashedPassword) {
    const [salt, key] = hashedPassword.split(":")
    const derivedKey = (await scrypt(plaintextPassword, salt, 64)) as NodeJS.ArrayBufferView
    return crypto.timingSafeEqual(Buffer.from(key, "hex"), derivedKey)
}

export async function findUser(userWhereInput) {
    const request = await fetch(process.env["NEXT_PUBLIC_HASURA_ENDPOINT"], {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Hasura-Admin-Secret": process.env["HASURA_GRAPHQL_ADMIN_SECRET"],
        },
        body: JSON.stringify({
            query: `
                query UserByEmail($where: user_bool_exp!) {
                    user(where: $where) {
                        id
                        email
                        password
                        refresh_token
                        refresh_token_expires_at
                    }
                }
            `,
            variables: {
                where: userWhereInput,
            },
        }),
    })
    const result = await request.json()
    const user = result.data.user[0]
    return user
}

export async function insertUser({ email, password, refresh_token, refresh_token_expires_at }) {
    const request = await fetch(process.env["NEXT_PUBLIC_HASURA_ENDPOINT"], {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Hasura-Admin-Secret": process.env["HASURA_GRAPHQL_ADMIN_SECRET"],
        },
        body: JSON.stringify({
            query: `
                mutation InsertUser($params: user_insert_input!) {
                    insert_user_one(object: $params) {
                        id
                        email
                    }
                }
            `,
            variables: {
                params: {
                    email,
                    password,
                    refresh_token,
                    refresh_token_expires_at,
                },
            },
        }),
    })
    const result = await request.json()
    console.log("insertUser", result)
    const user = result.data.insert_user_one
    return user
}

export async function updateUserRefreshToken({ id, refresh_token, refresh_token_expires_at }) {
    const request = await fetch(process.env["NEXT_PUBLIC_HASURA_ENDPOINT"], {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Hasura-Admin-Secret": process.env["HASURA_GRAPHQL_ADMIN_SECRET"],
        },
        body: JSON.stringify({
            query: `
                mutation UpdateUserRefreshToken($id: Int!, $refresh_token: String!, $refresh_token_expires_at: timestamptz!) {
                    update_user_by_pk(
                        pk_columns: { id: $id },
                        _set: {
                            refresh_token: $refresh_token,
                            refresh_token_expires_at: $refresh_token_expires_at
                        }
                    ) {
                        id
                        refresh_token
                    }
                }
            `,
            variables: {
                id,
                refresh_token,
                refresh_token_expires_at,
            },
        }),
    })
    const result = await request.json()
    console.log("updateUserRefreshToken", result)
    const user = result.data.update_user_by_pk
    return user
}
