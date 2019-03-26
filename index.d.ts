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
    checkSignature: (xml: string, log: any) => Promise<boolean>;
    computeSignature: (xml: string) => Promise<string>
    references: any[];
  }
}
