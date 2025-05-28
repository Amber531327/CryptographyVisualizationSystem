export interface KeyPair {
  publicKey: any;
  privateKey: any;
  [key: string]: any; // 允许其他属性，如ECDSA的keyPair
}

export interface SignatureResult {
  signature: any;
  r?: string;
  s?: string;
  messageHash?: string; // SHA-256消息哈希，用于显示
  n?: string; // 模数，用于显示
  salt?: string; // PSS填充使用的盐值（十六进制字符串）
  pBits?: number; // DSA参数p的位长
  qBits?: number; // DSA参数q的位长
  originalSignature?: string; // 原始签名值，用于检测签名篡改
}

export interface CryptoAlgorithm {
  generateKeys(): Promise<KeyPair>;
  sign(message: string, keys: KeyPair): Promise<SignatureResult>;
  verify(message: string, signature: any, keys: KeyPair): Promise<boolean>;
} 