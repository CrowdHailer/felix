import { Ok, Error } from "./gleam.mjs";
import * as SimpleWebAuthnServer from '@simplewebauthn/server';

const verify = SimpleWebAuthnServer.verifyRegistrationResponse

export async function verifyRegistrationResponse(body, expectedChallenge, expectedOrigin, expectedRPID, requireUserPresence, requireUserVerification) {
  const response = JSON.parse(body)
  const { verified, registrationInfo } = await verify({ response, expectedChallenge, expectedOrigin, expectedRPID, requireUserPresence, requireUserVerification })
  return new Ok([verified, registrationInfo])
}
const assert = SimpleWebAuthnServer.verifyAuthenticationResponse

export async function verifyAuthenticationResponse(body, expectedChallenge, expectedOrigin, expectedRPID, publicKey) {
  const response = JSON.parse(body)
  const credential = { publicKey: publicKey.buffer }
  const {verified, authenticationInfo} = await assert({ response, expectedChallenge, expectedOrigin, expectedRPID, credential })
  return new Ok([verified, authenticationInfo])
}