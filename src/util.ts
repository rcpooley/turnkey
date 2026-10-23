import { createHash, randomBytes } from 'node:crypto'

/** Fixed-width ISO 8601 UTC: compares correctly as text in every dialect. */
export const iso = (d: Date) => d.toISOString()
export const isoNow = () => new Date().toISOString()

export const sha256Hex = (s: string) => createHash('sha256').update(s).digest('hex')
export const randomId = (prefix: string) => `${prefix}${randomBytes(12).toString('hex')}`
export const randomSecret = (prefix: string) => prefix + randomBytes(32).toString('base64url')
