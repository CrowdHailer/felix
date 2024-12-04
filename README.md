# Felix

Allows user to create a new account or log in by providing a passkey.
WebAuthN/Fido2 integration.

[![Package Version](https://img.shields.io/hexpm/v/felix)](https://hex.pm/packages/felix)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/felix/)

## JS only

This library is bindings for the [SimpleWebAuthn server package](https://github.com/MasterKale/SimpleWebAuthn/).
Therefore it only works on JS server environments.

*I have a prototype for pure Gleam implementation but it is incomplete, get in touch if you need the use of an erlang based implementation.*

## Usage

```sh
npm i --save @simplewebauthn/server
gleam add felix@1
```

### Verify registration

```gleam
import felix/server

pub fn verify_registration(response: String) {
  // generated for each registration and sent to the client earlier
  let expected_challenge =
    bit_array.base64_url_encode(<<"secret challenge">>, False)

  use #(verified, info) <- promise.map_try(server.verify_registration(
    response: response,
    expected_challenge: expected_challenge,
    expected_origin: "http://localhost:8080",
    // rpid matches origin without scheme and port
    expected_rpid: "localhost",
    require_user_presence: False,
    require_user_verification: False,
  ))
  case verified {
    True ->
      // save the info.public_key in your database
      Ok(Nil)
    False -> Error("invalid")
  }
}
```

**NOTE:** client side registration can be handled using the [plinth](https://github.com/crowdhailer/plinth) library bindings to the Web credentials API.
```gleam
import plinth/browser/credentials
import plinth/browser/credentials/public_key

pub fn main(){
  let assert Ok(container) = credentials.from_navigator()
  let options =
    public_key.creation(
      <<"secret challenge">>,
      public_key.ES256,
      "New service",
      <<"my user id">>,
      "bob@example.com",
      "Bob",
    )
  use response <- promise.try_await(public_key.create(container, options))
  let response = json.to_string(public_key.to_json(response))
  // send to server to validate_registration
}
```

### Verify authentication

```gleam
import felix/server

pub fn verify_authentication_test(response) {
  // generated for each authentication
  let expected_challenge =
    bit_array.base64_url_encode(<<"another secret">>, False)
  let public_key = todo as "pull from DB"

  use #(verified, info) <- promise.map_try(server.verify_authentication(
    response: response,
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
```
**NOTE:** client side registration can be handled using the [plinth](https://github.com/crowdhailer/plinth) library bindings to the Web credentials API.
```gleam
import plinth/browser/credentials
import plinth/browser/credentials/public_key

pub fn main(){
  let assert Ok(container) = credentials.from_navigator()
  let options = public_key.request(<<"another secret">>)
  use response <- promise.try_await(public_key.get(container, options))
  let response = json.to_string(public_key.to_json(response))
  // send to server to validate_authentication
}
```

---

Further documentation can be found at <https://hexdocs.pm/felix>.

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests
```

## Credit

Created for [EYG](https://eyg.run/), a new integration focused programming language.