const crypto = require("crypto");

function uintToString(uintArray) {
  var encodedString = String.fromCharCode.apply(null, uintArray),
    decodedString = decodeURIComponent(escape(encodedString));
  return decodedString;
}

function WebCryptoToCrypto() {
  function mapper(alg) {
    if (alg.name === "RSASSA-PKCS1-v1_5") {
      switch (alg.hash.name) {
        case "SHA-1":
          return "RSA-SHA1";
        case "SHA-256":
          return "RSA-SHA256";
        case "SHA-512":
          return "RSA-SHA512";
        default:
          throw "Unknown alg";
      }
    } else if (alg.name === "HMAC") {
      switch (alg.hash.name) {
        case "SHA-1":
          return "SHA1";
        default:
          throw "Unknown alg";
      }
    }
    switch (alg.name) {
      case "SHA-1":
        return "sha1";
      case "SHA-512":
        return "sha512";
      case "SHA-256":
        return "sha256";
    }
    throw "Dunno the algorithm used";
  }

  return {
    digest: async (algorithm, message) => {
      const msg = uintToString(message);
      var shasum = crypto.createHash(mapper(algorithm));
      shasum.update(msg, "utf8");
      var res = shasum.digest("base64");
      return res;
    },
    sign: async (algorithm, signingKey, signedInfo) => {
      const msg = uintToString(signedInfo);
      if (algorithm.name == "HMAC") {
        var verifier = crypto.createHmac(mapper(algorithm), signingKey);
        verifier.update(msg);
        return verifier.digest("base64");
      }
      var signer = crypto.createSign(mapper(algorithm));
      signer.update(msg);
      return signer.sign(signingKey, "base64");
    },

    verify: async (algorithm, key, signature, value) => {
      const sig = uintToString(signature);
      const val = uintToString(value);
      //console.log("VERIFYING OUT ", key, sig, val);
      if (algorithm.name === "HMAC") {
        var verifier = crypto.createHmac(mapper(algorithm), key);
        verifier.update(val);
        return sig === verifier.digest("base64");
      }
      var verifier = crypto.createVerify(mapper(algorithm));
      verifier.update(val);
      var res = verifier.verify(key, sig, "base64");
      return res;
    },

    importKey: async (type, key, extractable, uses) => {
      throw "Import key Not implemented";
    }
  };
}

module.exports = WebCryptoToCrypto;
