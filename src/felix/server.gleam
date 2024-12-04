import gleam/dynamic.{type Dynamic}
import gleam/javascript/promise.{type Promise}
import gleam/option.{type Option, None, Some}
import gleam/result

pub type WebAuthnCredential {
  WebAuthnCredential(
    id: String,
    public_key: BitArray,
    // Number of times this authenticator is expected to have been used
    counter: Int,
    // From browser's `startRegistration()` -> RegistrationCredentialJSON.transports (API L2 and up)
    //   transports?: AuthenticatorTransportFuture[],
  )
}

pub type DeviceType {
  SingleDevice
  MultiDevice
}

fn device_type_decoder(raw) {
  use str <- result.try(dynamic.string(raw))
  case str {
    "singleDevice" -> Ok(SingleDevice)
    "multiDevice" -> Ok(MultiDevice)
    _ -> Error([dynamic.DecodeError("device type", str, [])])
  }
}

@external(javascript, "../felix_ffi.mjs", "verifyRegistrationResponse")
fn do_verify_registration(
  response: String,
  expected_challenge: String,
  expected_origin: String,
  expected_rpid: String,
  require_user_presence: Bool,
  require_user_verification: Bool,
) -> Promise(Result(#(Bool, Dynamic), String))

pub type RegistrationInfo {
  RegistrationInfo(
    fmt: String,
    aaguid: String,
    credential: WebAuthnCredential,
    attestation_object: BitArray,
    user_verified: Bool,
    credential_device_type: DeviceType,
    credential_backed_up: Bool,
    origin: String,
    rp_id: Option(String),
  )
}

fn registration_info_decoder(raw) {
  dynamic.decode9(
    RegistrationInfo,
    dynamic.field("fmt", dynamic.string),
    dynamic.field("aaguid", dynamic.string),
    dynamic.field(
      "credential",
      dynamic.decode3(
        WebAuthnCredential,
        dynamic.field("id", dynamic.string),
        dynamic.field("publicKey", dynamic.bit_array),
        dynamic.field("counter", dynamic.int),
      ),
    ),
    dynamic.field("attestationObject", dynamic.bit_array),
    dynamic.field("userVerified", dynamic.bool),
    dynamic.field("credentialDeviceType", device_type_decoder),
    dynamic.field("credentialBackedUp", dynamic.bool),
    dynamic.field("origin", dynamic.string),
    dynamic.field("rpID", dynamic.optional(dynamic.string)),
  )(raw)
}

pub fn verify_registration(
  response response: String,
  expected_challenge expected_challenge: String,
  expected_origin expected_origin: String,
  expected_rpid expected_rpid: String,
  require_user_presence require_user_presence: Bool,
  require_user_verification require_user_verification: Bool,
) {
  use #(verified, info) <- promise.map_try(do_verify_registration(
    response,
    expected_challenge,
    expected_origin,
    expected_rpid,
    require_user_presence,
    require_user_verification,
  ))
  case verified {
    False -> Ok(#(False, None))
    True -> {
      let assert Ok(info) = registration_info_decoder(info)
      Ok(#(True, Some(info)))
    }
  }
}

pub type AuthenticationInfo {
  AuthenticationInfo(
    new_counter: Int,
    user_verified: Bool,
    credential_device_type: DeviceType,
    credential_backed_up: Bool,
    origin: String,
    rp_id: String,
  )
}

fn authentication_info_decoder(raw) {
  dynamic.decode6(
    AuthenticationInfo,
    dynamic.field("newCounter", dynamic.int),
    dynamic.field("userVerified", dynamic.bool),
    dynamic.field("credentialDeviceType", device_type_decoder),
    dynamic.field("credentialBackedUp", dynamic.bool),
    dynamic.field("origin", dynamic.string),
    dynamic.field("rpID", dynamic.string),
  )(raw)
}

@external(javascript, "../felix_ffi.mjs", "verifyAuthenticationResponse")
fn do_verify_authentication(
  response response: String,
  expected_challenge expected_challenge: String,
  expected_origin expected_origin: String,
  expected_rpid expected_rpid: String,
  public_key public_key: BitArray,
  require_user_verification require_user_verification: Bool,
) -> Promise(Result(#(Bool, Dynamic), String))

pub fn verify_authentication(
  response response: String,
  expected_challenge expected_challenge: String,
  expected_origin expected_origin: String,
  expected_rpid expected_rpid: String,
  public_key public_key: BitArray,
  require_user_verification require_user_verification: Bool,
) {
  use #(verified, info) <- promise.map_try(do_verify_authentication(
    response,
    expected_challenge,
    expected_origin,
    expected_rpid,
    public_key,
    require_user_verification,
  ))
  let assert Ok(info) = authentication_info_decoder(info)
  Ok(#(verified, info))
}
