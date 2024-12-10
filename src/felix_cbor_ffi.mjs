import cbor from "cbor";

export function decode(bitArray) {
  return cbor.decode(bitArray.buffer)
}