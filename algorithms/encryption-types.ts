export interface KeyPair {
  publicKey: any;
  privateKey: any;
  [key: string]: any; // 允许其他属性
}

export interface EncryptionResult {
  ciphertext: string;
  ephemeralKey?: any; // ElGamal和ECC需要临时密钥
  iv?: string; // 初始化向量，用于某些模式
  metadata?: any; // 加密所需的额外数据
}

export interface EncryptionAlgorithm {
  name: string; // 算法名称
  description: string; // 算法描述
  generateKeys(): Promise<KeyPair>;
  encrypt(message: string, publicKey: any): Promise<EncryptionResult>;
  decrypt(encryptionResult: EncryptionResult, privateKey: any): Promise<string>;
} 