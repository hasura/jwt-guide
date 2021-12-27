import crypto from "crypto"

export function uuidv4(): string {
    // @ts-ignore
    return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, (c) =>
        // @ts-ignore
        (c ^ (crypto.webcrypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))).toString(16)
    )
}

export function getJwtToken() {
    return sessionStorage.getItem("jwt")
}

export function setJwtToken(token) {
    sessionStorage.setItem("jwt", token)
}

export function getRefreshToken() {
    return sessionStorage.getItem("refreshToken")
}

export function setRefreshToken(token) {
    sessionStorage.setItem("refreshToken", token)
}
