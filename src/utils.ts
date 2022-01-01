export function assertIsUint8Array(arg: any, message?: string): asserts arg is Uint8Array {
  if (!(arg instanceof Uint8Array)) throw new TypeError(message);
}

export function assertLength(arg: ArrayLike<any>, expectedLength: number, message?: string) {
  if (arg.length !== expectedLength) throw new RangeError(message);
}

export function assertBufferIsIPv4Length(buffer: Uint8Array, message?: string) {
  return assertLength(buffer, 4, message);
}

export function assertBufferIsIPv6Length(buffer: Uint8Array, message?: string) {
  return assertLength(buffer, 16, message);
}

export function assertBufferIsIPv4Or6Length(buffer: Uint8Array, message?: string) {
  if (buffer.length !== 4 && buffer.length !== 16) {
    throw new RangeError(message);
  }
}
