import felix/server
import gleam/bit_array
import gleam/javascript/promise
import gleam/option
import gleeunit
import gleeunit/should

pub fn main() {
  gleeunit.main()
}

const create_credentials = "{\"authenticatorAttachment\":\"cross-platform\",\"clientExtensionResults\":{},\"id\":\"6Dl8NoapOzxuvFFx8LpO0A\",\"rawId\":\"6Dl8NoapOzxuvFFx8LpO0A\",\"response\":{\"attestationObject\":\"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEOg5fDaGqTs8brxRcfC6TtClAQIDJiABIVggsGbipYhVHO6j0xErAoDMxtKdyBDhwaP5_ohxSFSteHYiWCAR1aKgOd3Olw1k7pUbJqmU6Ga7XxBSbCEVQTBdy4AQXQ\",\"authenticatorData\":\"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEOg5fDaGqTs8brxRcfC6TtClAQIDJiABIVggsGbipYhVHO6j0xErAoDMxtKdyBDhwaP5_ohxSFSteHYiWCAR1aKgOd3Olw1k7pUbJqmU6Ga7XxBSbCEVQTBdy4AQXQ\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZFhObFpDQnBiaUJoZEhSbGMzUmhkR2x2YmciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ\",\"publicKey\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsGbipYhVHO6j0xErAoDMxtKdyBDhwaP5_ohxSFSteHYR1aKgOd3Olw1k7pUbJqmU6Ga7XxBSbCEVQTBdy4AQXQ\",\"publicKeyAlgorithm\":-7,\"transports\":[\"hybrid\",\"internal\"]},\"type\":\"public-key\"}"

const get_credentials = "{\"authenticatorAttachment\":\"cross-platform\",\"clientExtensionResults\":{},\"id\":\"6Dl8NoapOzxuvFFx8LpO0A\",\"rawId\":\"6Dl8NoapOzxuvFFx8LpO0A\",\"response\":{\"authenticatorData\":\"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYlhrZ1ptbHljM1FnWTI5dGJXbDAiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9\",\"signature\":\"MEQCHxn-UJOAx0tiaIExqcToMg8aIKXvWMygf4EhDQ31bsMCIQDkP9tgFMEmFaXEoif4IEQBRCvI4NrDC-sUfliGZg2tlw\",\"userHandle\":\"dGVzdA\"},\"type\":\"public-key\"}"

const public_key = <<
  165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 176, 102, 226, 165, 136, 85, 28, 238, 163,
  211, 17, 43, 2, 128, 204, 198, 210, 157, 200, 16, 225, 193, 163, 249, 254, 136,
  113, 72, 84, 173, 120, 118, 34, 88, 32, 17, 213, 162, 160, 57, 221, 206, 151,
  13, 100, 238, 149, 27, 38, 169, 148, 232, 102, 187, 95, 16, 82, 108, 33, 21,
  65, 48, 93, 203, 128, 16, 93,
>>

pub fn verify_registration_test() {
  // generated for each registration
  let expected_challenge =
    bit_array.base64_url_encode(<<"used in attestation">>, False)

  use #(verified, info) <- promise.map_try(server.verify_registration(
    response: create_credentials,
    expected_challenge: expected_challenge,
    expected_origin: "http://localhost:8080",
    expected_rpid: "localhost",
    require_user_presence: False,
    require_user_verification: False,
  ))
  verified
  |> should.be_true
  let assert option.Some(info) = info
  info.credential
  |> should.equal(server.WebAuthnCredential(
    id: "6Dl8NoapOzxuvFFx8LpO0A",
    public_key: public_key,
    counter: 0,
  ))
  info.user_verified
  |> should.be_true
  info.credential_device_type
  |> should.equal(server.MultiDevice)
  info.credential_backed_up
  |> should.be_true
  info.origin
  |> should.equal("http://localhost:8080")
  Ok(Nil)
}

pub fn verify_authentication_test() {
  // generated for each authentication
  let expected_challenge =
    bit_array.base64_url_encode(<<"my first commit">>, False)

  use #(verified, info) <- promise.map_try(server.verify_authentication(
    response: get_credentials,
    expected_challenge: expected_challenge,
    expected_origin: "http://localhost:8080",
    expected_rpid: "localhost",
    public_key: public_key,
    require_user_verification: False,
  ))
  verified
  |> should.be_true
  info.user_verified
  |> should.be_true
  info.credential_device_type
  |> should.equal(server.MultiDevice)
  info.credential_backed_up
  |> should.be_true
  info.origin
  |> should.equal("http://localhost:8080")
  info.rp_id
  |> should.equal("localhost")
  Ok(Nil)
}
