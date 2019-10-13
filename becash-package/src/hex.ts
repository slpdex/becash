export function bufferToHex(buffer: Uint8Array): string {
    let s = '', h = '0123456789abcdef';
    buffer.forEach((v) => { s += h[v >> 4] + h[v & 15]; });
    return s;
}

export function hexToBuffer(hex: string): Uint8Array {
    if (typeof hex !== 'string') {
      throw new TypeError('Expected input to be a string')
    }
    if ((hex.length % 2) !== 0) {
      throw new RangeError('Expected string to be an even number of characters')
    }
    var array = new Uint8Array(hex.length / 2)
    for (var i = 0; i < hex.length; i += 2) {
      array[i / 2] = parseInt(hex.substring(i, i + 2), 16)
    }
    return array
}
