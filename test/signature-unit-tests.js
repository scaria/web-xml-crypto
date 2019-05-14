var select = require("xpath").select,
  dom = require("xmldom").DOMParser,
  SignedXml = require("../lib/signed-xml.js").SignedXml,
  FileKeyInfo = require("../lib/signed-xml.js").FileKeyInfo,
  fs = require("fs");

module.exports = {
  "signer adds increasing id atributes to elements": async function(test) {
    test.expect();
    await verifyAddsId(test, "wssecurity", "equal");
    await verifyAddsId(test, null, "different");
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer does not duplicate existing id attributes": async function(test) {
    test.expect();
    await verifyDoesNotDuplicateIdAttributes(test, null, "");
    await verifyDoesNotDuplicateIdAttributes(test, "wssecurity", "wsu:");
    console.log("-------Test Complete----------\n\n");
    test.done();
  },

  "signer adds custom attributes to the signature root node": async function(
    test
  ) {
    test.expect();
    await verifyAddsAttrs(test);
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer appends signature to the root node by default": async function(test) {
    test.expect();
    var xml =
      "<root><name>xml-crypto</name><repository>github</repository></root>";
    var sig = new SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference("//*[local-name(.)='name']");
    await sig.computeSignature(xml);
    var doc = new dom().parseFromString(sig.getSignedXml());
    test.strictEqual(
      doc.documentElement.lastChild.localName,
      "Signature",
      "the signature must be appended to the root node by default"
    );
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer appends signature to a reference node": async function(test) {
    test.expect();
    var xml =
      "<root><name>xml-crypto</name><repository>github</repository></root>";
    var sig = new SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference("//*[local-name(.)='repository']");
    await sig.computeSignature(xml, {
      location: {
        reference: "/root/name",
        action: "append"
      }
    });
    var doc = new dom().parseFromString(sig.getSignedXml());
    var referenceNode = select("/root/name", doc)[0];
    test.strictEqual(
      referenceNode.lastChild.localName,
      "Signature",
      "the signature should be appended to root/name"
    );
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer prepends signature to a reference node": async function(test) {
    test.expect();
    var xml =
      "<root><name>xml-crypto</name><repository>github</repository></root>";
    var sig = new SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference("//*[local-name(.)='repository']");
    await sig.computeSignature(xml, {
      location: {
        reference: "/root/name",
        action: "prepend"
      }
    });
    var doc = new dom().parseFromString(sig.getSignedXml());
    var referenceNode = select("/root/name", doc)[0];
    test.strictEqual(
      referenceNode.firstChild.localName,
      "Signature",
      "the signature should be prepended to root/name"
    );
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer inserts signature before a reference node": async function(test) {
    test.expect();
    var xml =
      "<root><name>xml-crypto</name><repository>github</repository></root>";
    var sig = new SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference("//*[local-name(.)='repository']");
    await sig.computeSignature(xml, {
      location: {
        reference: "/root/name",
        action: "before"
      }
    });
    var doc = new dom().parseFromString(sig.getSignedXml());
    var referenceNode = select("/root/name", doc)[0];
    test.strictEqual(
      referenceNode.previousSibling.localName,
      "Signature",
      "the signature should be inserted before to root/name"
    );
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer inserts signature after a reference node": async function(test) {
    test.expect();
    var xml =
      "<root><name>xml-crypto</name><repository>github</repository></root>";
    var sig = new SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference("//*[local-name(.)='repository']");
    await sig.computeSignature(xml, {
      location: {
        reference: "/root/name",
        action: "after"
      }
    });
    var doc = new dom().parseFromString(sig.getSignedXml());
    var referenceNode = select("/root/name", doc)[0];
    test.strictEqual(
      referenceNode.nextSibling.localName,
      "Signature",
      "the signature should be inserted after to root/name"
    );
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer creates signature with correct structure": async function(test) {
    test.expect();
    function DummyKeyInfo() {
      this.getKeyInfo = function(key) {
        return "dummy key info";
      };
    }
    function DummyDigest() {
      this.getHash = function(xml) {
        return "dummy digest";
      };
      this.getAlgorithmName = function() {
        return "dummy digest algorithm";
      };
    }
    function DummySignatureAlgorithm() {
      this.getSignature = function(xml, signingKey) {
        return "dummy signature";
      };
      this.getAlgorithmName = function() {
        return "dummy algorithm";
      };
    }
    function DummyTransformation() {
      this.process = function(node) {
        return "< x/>";
      };
      this.getAlgorithmName = function() {
        return "dummy transformation";
      };
    }
    function DummyCanonicalization() {
      this.process = function(node) {
        return "< x/>";
      };
      this.getAlgorithmName = function() {
        return "dummy canonicalization";
      };
    }
    var xml =
      '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';
    var sig = new SignedXml();
    SignedXml.CanonicalizationAlgorithms[
      "http://DummyTransformation"
    ] = DummyTransformation;
    SignedXml.CanonicalizationAlgorithms[
      "http://DummyCanonicalization"
    ] = DummyCanonicalization;
    SignedXml.HashAlgorithms["http://dummyDigest"] = DummyDigest;
    SignedXml.SignatureAlgorithms[
      "http://dummySignatureAlgorithm"
    ] = DummySignatureAlgorithm;
    sig.signatureAlgorithm = "http://dummySignatureAlgorithm";
    sig.keyInfoProvider = new DummyKeyInfo();
    sig.canonicalizationAlgorithm = "http://DummyCanonicalization";
    sig.addReference(
      "//*[local-name(.)='x']",
      ["http://DummyTransformation"],
      "http://dummyDigest"
    );
    sig.addReference(
      "//*[local-name(.)='y']",
      ["http://DummyTransformation"],
      "http://dummyDigest"
    );
    sig.addReference(
      "//*[local-name(.)='w']",
      ["http://DummyTransformation"],
      "http://dummyDigest"
    );
    await sig.computeSignature(xml);
    var signature = sig.getSignatureXml();
    var expected =
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      "<SignedInfo>" +
      '<CanonicalizationMethod Algorithm="dummy canonicalization" />' +
      '<SignatureMethod Algorithm="dummy algorithm" />' +
      '<Reference URI="#_0">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation" />' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm" />' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_1">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation" />' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm" />' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_2">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation" />' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm" />' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      "</SignedInfo>" +
      "<SignatureValue>dummy signature</SignatureValue>" +
      "<KeyInfo>" +
      "dummy key info" +
      "</KeyInfo>" +
      "</Signature>";
    test.equal(expected, signature, "wrong signature format");
    var signedXml = sig.getSignedXml();
    var expectedSignedXml =
      '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      "<SignedInfo>" +
      '<CanonicalizationMethod Algorithm="dummy canonicalization"/>' +
      '<SignatureMethod Algorithm="dummy algorithm"/>' +
      '<Reference URI="#_0">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_1">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_2">' +
      "<Transforms>" +
      '<Transform Algorithm="dummy transformation"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<DigestValue>dummy digest</DigestValue>" +
      "</Reference>" +
      "</SignedInfo>" +
      "<SignatureValue>dummy signature</SignatureValue>" +
      "<KeyInfo>" +
      "dummy key info" +
      "</KeyInfo>" +
      "</Signature>" +
      "</root>";
    test.equal(expectedSignedXml, signedXml, "wrong signedXml format");
    var originalXmlWithIds = sig.getOriginalXmlWithIds();
    var expectedOriginalXmlWithIds =
      '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z></root>';
    test.equal(
      expectedOriginalXmlWithIds,
      originalXmlWithIds,
      "wrong OriginalXmlWithIds"
    );
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer creates signature with correct structure (with prefix)": async function(
    test
  ) {
    test.expect();
    var prefix = "ds";
    function DummyKeyInfo() {
      this.getKeyInfo = function(key) {
        return "<ds:dummy>dummy key info</ds:dummy>";
      };
    }
    function DummyDigest() {
      this.getHash = function(xml) {
        return "dummy digest";
      };
      this.getAlgorithmName = function() {
        return "dummy digest algorithm";
      };
    }
    function DummySignatureAlgorithm() {
      this.getSignature = function(xml, signingKey) {
        return "dummy signature";
      };
      this.getAlgorithmName = function() {
        return "dummy algorithm";
      };
    }
    function DummyTransformation() {
      this.process = function(node) {
        return "< x/>";
      };
      this.getAlgorithmName = function() {
        return "dummy transformation";
      };
    }
    function DummyCanonicalization() {
      this.process = function(node) {
        return "< x/>";
      };
      this.getAlgorithmName = function() {
        return "dummy canonicalization";
      };
    }
    var xml =
      '<root><x xmlns="ns"></x><y attr="value"></y><z><w></w></z></root>';
    var sig = new SignedXml();
    SignedXml.CanonicalizationAlgorithms[
      "http://DummyTransformation"
    ] = DummyTransformation;
    SignedXml.CanonicalizationAlgorithms[
      "http://DummyCanonicalization"
    ] = DummyCanonicalization;
    SignedXml.HashAlgorithms["http://dummyDigest"] = DummyDigest;
    SignedXml.SignatureAlgorithms[
      "http://dummySignatureAlgorithm"
    ] = DummySignatureAlgorithm;
    sig.signatureAlgorithm = "http://dummySignatureAlgorithm";
    sig.keyInfoProvider = new DummyKeyInfo();
    sig.canonicalizationAlgorithm = "http://DummyCanonicalization";
    sig.addReference(
      "//*[local-name(.)='x']",
      ["http://DummyTransformation"],
      "http://dummyDigest"
    );
    sig.addReference(
      "//*[local-name(.)='y']",
      ["http://DummyTransformation"],
      "http://dummyDigest"
    );
    sig.addReference(
      "//*[local-name(.)='w']",
      ["http://DummyTransformation"],
      "http://dummyDigest"
    );
    await sig.computeSignature(xml, { prefix: prefix });
    var signature = sig.getSignatureXml();
    var expected =
      '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      "<ds:SignedInfo>" +
      '<ds:CanonicalizationMethod Algorithm="dummy canonicalization" />' +
      '<ds:SignatureMethod Algorithm="dummy algorithm" />' +
      '<ds:Reference URI="#_0">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation" />' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm" />' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      '<ds:Reference URI="#_1">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation" />' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm" />' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      '<ds:Reference URI="#_2">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation" />' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm" />' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      "</ds:SignedInfo>" +
      "<ds:SignatureValue>dummy signature</ds:SignatureValue>" +
      "<ds:KeyInfo>" +
      "<ds:dummy>dummy key info</ds:dummy>" +
      "</ds:KeyInfo>" +
      "</ds:Signature>";
    test.equal(expected, signature, "wrong signature format");
    var signedXml = sig.getSignedXml();
    var expectedSignedXml =
      '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
      '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      "<ds:SignedInfo>" +
      '<ds:CanonicalizationMethod Algorithm="dummy canonicalization"/>' +
      '<ds:SignatureMethod Algorithm="dummy algorithm"/>' +
      '<ds:Reference URI="#_0">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation"/>' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      '<ds:Reference URI="#_1">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation"/>' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      '<ds:Reference URI="#_2">' +
      "<ds:Transforms>" +
      '<ds:Transform Algorithm="dummy transformation"/>' +
      "</ds:Transforms>" +
      '<ds:DigestMethod Algorithm="dummy digest algorithm"/>' +
      "<ds:DigestValue>dummy digest</ds:DigestValue>" +
      "</ds:Reference>" +
      "</ds:SignedInfo>" +
      "<ds:SignatureValue>dummy signature</ds:SignatureValue>" +
      "<ds:KeyInfo>" +
      "<ds:dummy>dummy key info</ds:dummy>" +
      "</ds:KeyInfo>" +
      "</ds:Signature>" +
      "</root>";
    test.equal(expectedSignedXml, signedXml, "wrong signedXml format");
    var originalXmlWithIds = sig.getOriginalXmlWithIds();
    var expectedOriginalXmlWithIds =
      '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z></root>';
    test.equal(
      expectedOriginalXmlWithIds,
      originalXmlWithIds,
      "wrong OriginalXmlWithIds"
    );
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer creates correct signature values": async function(test) {
    test.expect();
    var xml =
      '<root><x xmlns="ns" Id="_0"></x><y attr="value" Id="_1"></y><z><w Id="_2"></w></z></root>';
    var sig = new SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    sig.keyInfoProvider = null;
    sig.addReference("//*[local-name(.)='x']");
    sig.addReference("//*[local-name(.)='y']");
    sig.addReference("//*[local-name(.)='w']");
    await sig.computeSignature(xml);
    var signedXml = sig.getSignedXml();
    var expected =
      '<root><x xmlns="ns" Id="_0"/><y attr="value" Id="_1"/><z><w Id="_2"/></z>' +
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      "<SignedInfo>" +
      '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>' +
      '<Reference URI="#_0">' +
      "<Transforms>" +
      '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>' +
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
      "<DigestValue>b5GCZ2xpP5T7tbLWBTkOl4CYupQ=</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_1">' +
      "<Transforms>" +
      '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
      "<DigestValue>4Pq/sBri+AyOtxtSFsPSOyylyzk=</DigestValue>" +
      "</Reference>" +
      '<Reference URI="#_2">' +
      "<Transforms>" +
      '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
      "<DigestValue>6I7SDu1iV2YOajTlf+iMLIBfLnE=</DigestValue>" +
      "</Reference>" +
      "</SignedInfo>" +
      "<SignatureValue>NejzGB9MDUddKCt3GL2vJhEd5q6NBuhLdQc3W4bJI5q34hk7Hk6zBRoW3OliX+/f7Hpi9y0INYoqMSUfrsAVm3IuPzUETKlI6xiNZo07ULRj1DwxRo6cU66ar1EKUQLRuCZas795FjB8jvUI2lyhcax/00uMJ+Cjf4bwAQ+9gOQ=</SignatureValue>" +
      "</Signature>" +
      "</root>";
    test.equal(expected, signedXml, "wrong signature format");
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "correctly loads signature": function(test) {
    test.expect();
    passLoadSignature(test, "./test/static/valid_signature.xml");
    passLoadSignature(test, "./test/static/valid_signature.xml", true);
    passLoadSignature(
      test,
      "./test/static/valid_signature_with_root_level_sig_namespace.xml"
    );
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "verify valid signature": async function(test) {
    test.expect();
    await passValidSignature(test, "./test/static/valid_signature.xml");
    await passValidSignature(
      test,
      "./test/static/valid_signature_with_lowercase_id_attribute.xml"
    );
    await passValidSignature(
      test,
      "./test/static/valid_signature wsu.xml",
      "wssecurity"
    );
    await passValidSignature(
      test,
      "./test/static/valid_signature_with_reference_keyInfo.xml"
    );
    await passValidSignature(
      test,
      "./test/static/valid_signature_with_whitespace_in_digestvalue.xml"
    );
    await passValidSignature(test, "./test/static/valid_signature_utf8.xml");
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "verify valid signature on comment attack & canon should remove all comments": async function(
    test
  ) {
    test.expect();

    var xml = fs
      .readFileSync("./test/static/valid_signature_comment_attack.xml")
      .toString();
    var [res, sig] = await verifySignature(xml);

    const x = sig.canonize(xml);
    const attributes = select(
      `//*[local-name(.)='Assertion']/*[local-name(.)='AttributeStatement']/*[local-name(.)='Attribute']`,
      new dom().parseFromString(x)
    );

    test.equal(
      attributes[0].childNodes[0].childNodes[0].nodeValue,
      "сообщить@bar.com"
    ); //Comment should be removed

    test.equal(res, true);
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "fail invalid signature": async function(test) {
    test.expect();
    await failInvalidSignature(
      test,
      "./test/static/invalid_signature - signature value.xml"
    );
    await failInvalidSignature(
      test,
      "./test/static/invalid_signature - hash.xml"
    );
    await failInvalidSignature(
      test,
      "./test/static/invalid_signature - non existing reference.xml"
    );
    await failInvalidSignature(
      test,
      "./test/static/invalid_signature - changed content.xml"
    );
    await failInvalidSignature(
      test,
      "./test/static/invalid_signature - wsu - invalid signature value.xml",
      "wssecurity"
    );
    await failInvalidSignature(
      test,
      "./test/static/invalid_signature - wsu - hash.xml",
      "wssecurity"
    );
    await failInvalidSignature(
      test,
      "./test/static/invalid_signature - wsu - non existing reference.xml",
      "wssecurity"
    );
    await failInvalidSignature(
      test,
      "./test/static/invalid_signature - wsu - changed content.xml",
      "wssecurity"
    );
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "allow empty reference uri when signing": async function(test) {
    test.expect();
    var xml = "<root><x /></root>";
    var sig = new SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    sig.keyInfoProvider = null;
    sig.addReference(
      "//*[local-name(.)='root']",
      ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
      "http://www.w3.org/2000/09/xmldsig#sha1",
      "",
      "",
      "",
      true
    );
    await sig.computeSignature(xml);
    var signedXml = sig.getSignedXml();
    var doc = new dom().parseFromString(signedXml);
    var URI = select("//*[local-name(.)='Reference']/@URI", doc)[0];
    test.equal(
      URI.value,
      "",
      "uri should be empty but instead was " + URI.value
    );
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer appends signature to a non-existing reference node": async function(
    test
  ) {
    test.expect();
    var xml =
      "<root><name>xml-crypto</name><repository>github</repository></root>";
    var sig = new SignedXml();
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    sig.addReference("//*[local-name(.)='repository']");
    try {
      await sig.computeSignature(xml, {
        location: {
          reference: "/root/foobar",
          action: "append"
        }
      });
      test.ok(false);
    } catch (err) {
      test.ok(!(err instanceof TypeError));
    }
    console.log("-------Test Complete----------\n\n");
    test.done();
  },
  "signer adds existing prefixes": async function(test) {
    test.expect();
    function AssertionKeyInfo(assertionId) {
      this.getKeyInfo = function(key, prefix) {
        return (
          '<wsse:SecurityTokenReference wsse11:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1" wsu:Id="0" ' +
          'xmlns:wsse11="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"> ' +
          '<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">' +
          assertionId +
          "</wsse:KeyIdentifier>"
        );
        ("</wsse:SecurityTokenReference>");
      };
    }
    var xml =
      '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"> ' +
      "<SOAP-ENV:Header> " +
      "<wsse:Security " +
      'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ' +
      'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"> ' +
      "<Assertion></Assertion> " +
      "</wsse:Security> " +
      "</SOAP-ENV:Header> " +
      "</SOAP-ENV:Envelope>";
    var sig = new SignedXml();
    sig.keyInfoProvider = new AssertionKeyInfo(
      "_81d5fba5c807be9e9cf60c58566349b1"
    );
    sig.signingKey = fs.readFileSync("./test/static/client.pem");
    await sig.computeSignature(xml, {
      prefix: "ds",
      location: {
        reference: "//Assertion",
        action: "after"
      },
      existingPrefixes: {
        wsse:
          "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        wsu:
          "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
      }
    });
    result = sig.getSignedXml();
    test.equal((result.match(/xmlns:wsu=/g) || []).length, 1);
    test.equal((result.match(/xmlns:wsse=/g) || []).length, 1);
    console.log("-------Test Complete----------\n\n");
    test.done();
  }
};

async function passValidSignature(test, file, mode) {
  var xml = fs.readFileSync(file).toString();
  var [res] = await verifySignature(xml, mode);
  test.equal(
    true,
    res,
    "expected signature to be valid, but it was reported invalid"
  );
}

function passLoadSignature(test, file, toString) {
  var xml = fs.readFileSync(file).toString();
  var doc = new dom().parseFromString(xml);
  var node = select(
    "/*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc
  )[0];
  var sig = new SignedXml();
  sig.loadSignature(toString ? node.toString() : node);

  test.equal(
    "http://www.w3.org/2001/10/xml-exc-c14n#",
    sig.canonicalizationAlgorithm,
    "wrong canonicalization method"
  );

  test.equal(
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    sig.signatureAlgorithm,
    "wrong signature method"
  );

  test.equal(
    "PI2xGt3XrVcxYZ34Kw7nFdq75c7Mmo7J0q7yeDhBprHuJal/KV9KyKG+Zy3bmQIxNwkPh0KMP5r1YMTKlyifwbWK0JitRCSa0Fa6z6+TgJi193yiR5S1MQ+esoQT0RzyIOBl9/GuJmXx/1rXnqrTxmL7UxtqKuM29/eHwF0QDUI=",
    sig.signatureValue,
    "wrong signature value"
  );

  var keyInfo = select(
    "//*[local-name(.)='KeyInfo']/*[local-name(.)='dummyKey']",
    sig.keyInfo[0]
  )[0];
  test.equal(
    keyInfo.firstChild.data,
    "1234",
    "keyInfo clause not correctly loaded"
  );

  test.equal(3, sig.references.length);

  var digests = [
    "b5GCZ2xpP5T7tbLWBTkOl4CYupQ=",
    "K4dI497ZCxzweDIrbndUSmtoezY=",
    "sH1gxKve8wlU8LlFVa2l6w3HMJ0="
  ];

  for (var i = 0; i < sig.references.length; i++) {
    var ref = sig.references[i];
    var expectedUri = "#_" + i;
    test.equal(
      expectedUri,
      ref.uri,
      "wrong uri for index " +
        i +
        ". expected: " +
        expectedUri +
        " actual: " +
        ref.uri
    );
    test.equal(1, ref.transforms.length);
    test.equal("http://www.w3.org/2001/10/xml-exc-c14n#", ref.transforms[0]);
    test.equal(digests[i], ref.digestValue);
    test.equal("http://www.w3.org/2000/09/xmldsig#sha1", ref.digestAlgorithm);
  }
}

async function failInvalidSignature(test, file, mode) {
  var xml = fs.readFileSync(file).toString();
  var [res] = await verifySignature(xml, mode, true);
  test.equal(
    false,
    res,
    "expected signature to be invalid, but it was reported valid"
  );
}

async function verifySignature(xml, mode, silent = false) {
  var doc = new dom().parseFromString(xml);
  var node = select(
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc
  )[0];

  var sig = new SignedXml(mode);
  sig.keyInfoProvider = new FileKeyInfo(
    fs.readFileSync("./test/static/client_public.pem")
  );

  sig.loadSignature(node);
  var res = await sig.checkSignature(xml);
  !silent &&
    sig.validationErrors &&
    sig.validationErrors.length > 0 &&
    console.log(sig.validationErrors);
  return [res, sig];
}

async function verifyDoesNotDuplicateIdAttributes(test, mode, prefix) {
  var xml =
    "<x xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' " +
    prefix +
    "Id='_1'></x>";
  var sig = new SignedXml(mode);
  sig.signingKey = fs.readFileSync("./test/static/client.pem");
  sig.addReference("//*[local-name(.)='x']");
  await sig.computeSignature(xml);
  var signedxml = sig.getOriginalXmlWithIds();
  var doc = new dom().parseFromString(signedxml);
  var attrs = select("//@*", doc);
  test.equals(2, attrs.length, "wrong nuber of attributes");
}

async function verifyAddsId(test, mode, nsMode) {
  var xml = '<x xmlns="ns"></x><y attr="value"></y><z><w></w></z>';
  var sig = new SignedXml(mode);
  sig.signingKey = fs.readFileSync("./test/static/client.pem");

  sig.addReference("//*[local-name(.)='x']");
  sig.addReference("//*[local-name(.)='y']");
  sig.addReference("//*[local-name(.)='w']");

  await sig.computeSignature(xml);
  var signedxml = sig.getOriginalXmlWithIds();
  var doc = new dom().parseFromString(signedxml);

  op = nsMode == "equal" ? "=" : "!=";

  var xpath =
    "//*[local-name(.)='{elem}' and '_{id}' = @*[local-name(.)='Id' and namespace-uri(.)" +
    op +
    "'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd']]";

  //verify each of the signed nodes now has an "Id" attribute with the right value
  nodeExists(test, doc, xpath.replace("{id}", "0").replace("{elem}", "x"));
  nodeExists(test, doc, xpath.replace("{id}", "1").replace("{elem}", "y"));
  nodeExists(test, doc, xpath.replace("{id}", "2").replace("{elem}", "w"));
}

async function verifyAddsAttrs(test) {
  var xml =
    '<root xmlns="ns"><name>xml-crypto</name><repository>github</repository></root>';
  var sig = new SignedXml();
  var attrs = {
    Id: "signatureTest",
    data: "dataValue",
    xmlns: "http://custom-xmlns#"
  };

  sig.signingKey = fs.readFileSync("./test/static/client.pem");

  sig.addReference("//*[local-name(.)='name']");

  await sig.computeSignature(xml, {
    attrs: attrs
  });

  var signedXml = sig.getSignatureXml();
  var doc = new dom().parseFromString(signedXml);
  var signatureNode = doc.documentElement;

  test.strictEqual(
    signatureNode.getAttribute("Id"),
    attrs.Id,
    'Id attribute is not equal to the expected value: "' + attrs.Id + '"'
  );
  test.strictEqual(
    signatureNode.getAttribute("data"),
    attrs.data,
    'data attribute is not equal to the expected value: "' + attrs.data + '"'
  );
  test.notStrictEqual(
    signatureNode.getAttribute("xmlns"),
    attrs.xmlns,
    "xmlns attribute can not be overridden"
  );
  test.strictEqual(
    signatureNode.getAttribute("xmlns"),
    "http://www.w3.org/2000/09/xmldsig#",
    'xmlns attribute is not equal to the expected value: "http://www.w3.org/2000/09/xmldsig#"'
  );
}

function nodeExists(test, doc, xpath) {
  if (!doc && !xpath) return;
  var node = select(xpath, doc);
  test.ok(node.length == 1, "xpath " + xpath + " not found");
}
