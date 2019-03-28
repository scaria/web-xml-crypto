declare module "web-xml-crypto" {
  export class FileKeyInfo {
    constructor(content: Uint8Array | Buffer);
    getKey: (...args: any[]) => string;
    getKeyInfo: (...args: any[]) => string;
  }
  export class SignedXml {
    signatureAlgorithm: any;
    keyInfoProvider: FileKeyInfo;
    loadSignature: (node: any) => void;
    checkSignature: (xml: string, xmlDoc?: Document) => boolean;
    computeSignature: (xml: string) => string;
    references: any[];
  }
}
