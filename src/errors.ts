/** Every error Turnkey throws on purpose. `status` is the HTTP status an adapter answers with. */
export class TurnkeyError extends Error {
  override name = 'TurnkeyError'
  constructor(
    readonly status: number,
    message: string,
    /** A stable, machine-readable reason: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `schema`. */
    readonly code: string,
  ) {
    super(message)
  }

  /** The JSON body an adapter sends: `{error, code}`. */
  toJSON(): { error: string; code: string } {
    return { error: this.message, code: this.code }
  }
}

export const badRequest = (msg: string) => new TurnkeyError(400, msg, 'bad_request')
export const unauthorized = (msg = 'authentication required') => new TurnkeyError(401, msg, 'unauthorized')
export const forbidden = (msg: string) => new TurnkeyError(403, msg, 'forbidden')
export const notFound = (msg: string) => new TurnkeyError(404, msg, 'not_found')
export const conflict = (msg: string) => new TurnkeyError(409, msg, 'conflict')
export const schemaError = (msg: string) => new TurnkeyError(500, msg, 'schema')
