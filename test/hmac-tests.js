var crypto = require("../index");
var xpath = require("xpath");
var xmldom = require("xmldom");
var fs = require("fs");

exports["test validating HMAC signature"] = async function(test) {
  var xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xpath.select(
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc
  )[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo(
    fs.readFileSync("./test/static/hmac.key")
  );
  sig.loadSignature(signature);
  var result = await sig.checkSignature(xml);
  test.equal(result, true);
  console.log("-------Test Complete----------\n\n");
  test.done();
};

exports["test HMAC signature with incorrect key"] = async function(test) {
  var xml = fs.readFileSync("./test/static/hmac_signature.xml", "utf-8");
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xpath.select(
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc
  )[0];
  var sig = new crypto.SignedXml();
  sig.keyInfoProvider = new crypto.FileKeyInfo(
    fs.readFileSync("./test/static/hmac-foobar.key")
  );
  sig.loadSignature(signature);
  var result = await sig.checkSignature(xml);
  test.equal(result, false);
  console.log("-------Test Complete----------\n\n");
  test.done();
};

exports["test create and validate HMAC signature"] = async function(test) {
  var xml =
    "<library>" +
    "<book>" +
    "<name>Harry Potter</name>" +
    "</book>" +
    "</library>";
  var sig = new crypto.SignedXml();
  sig.signingKey = fs.readFileSync("./test/static/hmac.key");
  sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
  sig.addReference("//*[local-name(.)='book']");
  await sig.computeSignature(xml);

  var doc = new xmldom.DOMParser().parseFromString(sig.getSignedXml());
  var signature = xpath.select(
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    doc
  )[0];
  var verify = new crypto.SignedXml();
  verify.keyInfoProvider = new crypto.FileKeyInfo(
    fs.readFileSync("./test/static/hmac.key")
  );
  verify.loadSignature(signature);
  var result = await verify.checkSignature(sig.getSignedXml());
  test.equal(result, true);
  console.log("-------Test Complete----------\n\n");
  test.done();
};
