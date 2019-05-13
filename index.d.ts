declare module "web-xml-crypto" {
  export class FileKeyInfo {
    constructor(content: Uint8Array | Buffer);
    getKey: (...args: any[]) => string;
    getKeyInfo: (...args: any[]) => string;
  }

  type SignatureAlgorithm = {
    getSignature(info: string, key: Buffer | Uint8Array): string;
    verifySignature(
      info: string,
      key: Buffer | Uint8Array,
      signature: string
    ): boolean;
  };

  type CanonizationAlgorithm = {};
  type HashAlgorithm = {
    getHash(string: string): string;
    getAlgorithmName(): string;
  };

  export class SignedXml {
    signingKey: Buffer | Uint8Array;
    signatureAlgorithm: any;
    keyInfoProvider: FileKeyInfo | null;
    addReference(
      xpath?: string,
      transforms?: any,
      digestAlgorithm?: any,
      uri?: any,
      digestValue?: any,
      inclusiveNamespacesPrefixList?: any,
      isEmptyUri?: any
    ): void;
    loadSignature: (node: any) => void;
    checkSignature: (xml: string, xmlDoc?: Document) => boolean;
    computeSignature: (
      xml: string,
      oprts?: { prefix?: string; location?: any; attrs?: any }
    ) => void;
    validateSignatureValue(doc: Document): boolean;
    findSignatureAlgorithm(name: string): SignatureAlgorithm;
    findCanonicalizationAlgorithm(name: string): CanonizationAlgorithm;
    findHashAlgorithm(name: string): HashAlgorithm;
    validateReferences(doc: Document): boolean;
    loadReference(xpath: string): void;
    getKeyInfo(prefix: string): string;
    createReferences(doc: Document, prefix: string): string;
    getSignatureXml(): string;
    getOriginalXmlWithIds(): string;
    getSignedXml(): string;
    createSignature(info: string, prefix: string): string;
    createSignedInfo(doc: Document, prefix: string): string;
    ensureHasId(node: Node | Document): string;
    references: any[];
    canonize(mode?: string[], options?: any): string;
  }
}
