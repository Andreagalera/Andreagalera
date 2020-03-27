
const bcu = require('bigint-crypto-utils');

class PublicKey {
    constructor(e, n) {
      this.e = bcu.bigintToHex(e);
      this.n = bcu.bigintToHex(n);
    }
  }

  publicKey = new PublicKey(
    puKey.e,
    puKey.n
  )
  
  