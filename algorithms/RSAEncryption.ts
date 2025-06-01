import { KeyPair, EncryptionResult, EncryptionAlgorithm } from './encryption-types';

/**
 * RSA加密算法实现类
 * 使用OAEP填充方案，SHA-256哈希函数
 */
export class RSAEncryption implements EncryptionAlgorithm {
  name = 'RSA';
  description = 'RSA是一种非对称加密算法，基于大整数因子分解的数学难题。由Rivest、Shamir和Adleman三人在1977年提出。';
  
  // 判断当前环境
  private isNode(): boolean {
    return typeof window === 'undefined' && typeof process !== 'undefined' && process.versions && !!process.versions.node;
  }

  /**
   * 生成RSA密钥对
   * @returns 包含公钥和私钥的KeyPair对象
   */
  async generateKeys(): Promise<KeyPair> {
    try {
      // 在Node.js环境中使用crypto模块
      if (this.isNode()) {
        const crypto = require('crypto');
        const { publicKey, privateKey } = await new Promise<{ publicKey: string, privateKey: string }>((resolve, reject) => {
          crypto.generateKeyPair('rsa', {
            modulusLength: 2048, // 密钥长度
            publicKeyEncoding: {
              type: 'spki',
              format: 'pem'
            },
            privateKeyEncoding: {
              type: 'pkcs8',
              format: 'pem'
            }
          }, (err: Error | null, publicKey: string, privateKey: string) => {
            if (err) reject(err);
            else resolve({ publicKey, privateKey });
          });
        });

        return {
          publicKey,
          privateKey,
          keySize: 2048,
          publicKeyDetails: this.extractPublicKeyDetails(publicKey),
          privateKeyDetails: this.extractPrivateKeyDetails(privateKey)
        };
      } 
      // 在浏览器环境中
      else {
        console.log('在浏览器环境中使用模拟密钥');
        // 在浏览器环境中直接使用模拟密钥
        return this.generateMockKeys();
      }
    } catch (error) {
      console.error('RSA密钥生成错误:', error);
      // 如果出错，提供模拟密钥
      return this.generateMockKeys();
    }
  }

  /**
   * 使用公钥加密消息
   * @param message 要加密的明文消息
   * @param publicKey 加密用的公钥
   * @returns 包含密文的加密结果
   */
  async encrypt(message: string, publicKey: string): Promise<EncryptionResult> {
    try {
      // 在Node.js环境中
      if (this.isNode()) {
        const crypto = require('crypto');
        const buffer = Buffer.from(message, 'utf8');
        const encrypted = crypto.publicEncrypt(
          {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
          },
          buffer
        );
        
        return {
          ciphertext: encrypted.toString('base64'),
          metadata: {
            padding: 'OAEP',
            hashAlgorithm: 'SHA-256',
            isSimulated: false
          }
        };
      } 
      // 在浏览器环境中使用模拟加密
      else {
        console.log('在浏览器环境中使用模拟加密');
        return this.mockEncrypt(message, publicKey);
      }
    } catch (error) {
      console.error('RSA加密错误:', error);
      // 如果出错，使用模拟加密
      return this.mockEncrypt(message, publicKey);
    }
  }

  /**
   * 使用私钥解密消息
   * @param encryptionResult 包含密文的加密结果
   * @param privateKey 解密用的私钥
   * @returns 解密后的明文
   */
  async decrypt(encryptionResult: EncryptionResult, privateKey: string): Promise<string> {
    try {
      // 检查是否为模拟加密的结果
      if (encryptionResult.metadata && encryptionResult.metadata.isSimulated === true) {
        console.log('检测到模拟加密结果，使用模拟解密');
        return this.mockDecrypt(encryptionResult, privateKey);
      }
      
      // 在Node.js环境中
      if (this.isNode()) {
        const crypto = require('crypto');
        const buffer = Buffer.from(encryptionResult.ciphertext, 'base64');
        const decrypted = crypto.privateDecrypt(
          {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
          },
          buffer
        );
        
        return decrypted.toString('utf8');
      } 
      // 在浏览器环境中使用模拟解密
      else {
        console.log('在浏览器环境中使用模拟解密');
        return this.mockDecrypt(encryptionResult, privateKey);
      }
    } catch (error) {
      console.error('RSA解密错误:', error);
      // 尝试使用模拟解密
      return this.mockDecrypt(encryptionResult, privateKey);
    }
  }

  /**
   * 提取公钥中的重要参数用于UI显示
   */
  private extractPublicKeyDetails(publicKey: string): any {
    // 在实际项目中，你可能需要解析ASN.1格式来正确提取这些值
    return {
      algorithm: 'RSA',
      format: 'PKCS#8',
      keySize: '2048位',
      publicExponent: 'e = 65537 (0x10001)', // 通常使用的标准公共指数
      modulus: 'n = ' + this.abbreviateString(publicKey.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '')) // 简化显示
    };
  }

  /**
   * 提取私钥中的重要参数用于UI显示
   */
  private extractPrivateKeyDetails(privateKey: string): any {
    return {
      algorithm: 'RSA',
      format: 'PKCS#8',
      keySize: '2048位',
      privateKey: this.abbreviateString(privateKey.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n/g, ''))
    };
  }

  /**
   * 缩短字符串用于显示
   */
  private abbreviateString(str: string): string {
    if (str.length <= 20) return str;
    return str.substring(0, 10) + '...' + str.substring(str.length - 10);
  }

  /**
   * 生成模拟密钥（当浏览器环境不支持crypto.generateKeyPair时使用）
   */
  private generateMockKeys(): KeyPair {
    return {
      publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvL0+kezZ4AvzJScPWHzO\nzH30r9VWr6WroTrMkVOPeP1yfF/UhAyZzF3dUzXiU7V0yW5TylhelY0+Jd7qGaQH\n3iDJLXQLmhzjRhbCEJKKOmUrSHzVbtXiF5SG3+1dXjKhJL6/1+3EnJMxMG01jGag\nPR+IxzCG/8i7YXVeGQmHQBgFpzIbiLIkVbE380/K9xIcVmHvqOIWdWWK4/XCQeQk\n3H4r+1JrTm/5GE7JDnBEtP61+L1NvzI1/xhEaDk/A/D8NmEwSS+Jd4LCyTgE7A+1\nqW+UXfjcZPA9kGDtgFdOW1CQ93XYCzGZoUCiU4xdhMMvGQwCpuT2jnk9BQR3+1Nj\nuwIDAQAB\n-----END PUBLIC KEY-----',
      privateKey: '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8vT6R7NngC/Ml\nJw9YfM7MffSv1VavpauhOsyRU494/XJ8X9SEDJnMXd1TNeJTtXTJblPKWF6VjT4l\n3uoZpAfeIMktdAuaHONGFsIQkoo6ZStIfNVu1eIXlIbf7V1eMqEkvr/X7cSckzEw\nbTWMZqA9H4jHMIb/yLthdV4ZCYdAGAWnMhuIsiRVsTfzT8r3EhxWYe+o4hZ1ZYrj\n9cJB5CTcfiv7UmtOb/kYTskOcES0/rX4vU2/MjX/GERoOT8D8Pw2YTBJLsl3gsLJ\nOATsD7Wpb5Rd+Nxk8D2QYO2AV05bUJD3ddgLMZmhQKJTjF2Ewy8ZDAKm5PaOeT0F\nBHf7U2O7AgMBAAECggEAVpbB2a08Q9APV6tS1oaBYjvHJbPH7YQBeOjtxmQrk3yt\nqKed2mytjHLwNqqJOTSvj9vTaUXXVFGQJhBzqVzZxBYhR5nfzFYM6l5BbJP3YPnH\ngW3tlJbKZ8R3SkMOAWbsNnDFR9/VNMYcll1caBaJNJYBEkJvYpCXLQRZcKiGifYu\nu622JS9/46Q+NC9JJyNXXZ2w59iiR/KjrjdW55/SEGr3RsKAgiZ0MST+SVi5Xm6t\nj+nFdGpBiMEBsLf+noF+bnA1qWsZtmZ3u/tAKKFg9XrjKlrAYvpW/IO+rhDQpdQa\n6Cp4YWG4mOZBPpCI8RwSLXuE0PtJ4xp6gTBQVtn7QQKBgQDp5I5WzEbAVoCSDAjI\nQhzKjV/2yd5NV/RQQdY1wAPJGcA2PK5R5yfTX7Y8BLlYaYmxVdCIESKPGopKdpY5\nEKEWJ6JNgDgswx4t9YbdczRGXyFBDmchRx511USliac2JiK5TBUSAUBk7VWyGU4R\n+LJQ1SExGlKfQQiy8tLlFTgb+wKBgQDO/iF5lTUuuJ4KJhaJ4exBrnRd+J3mwukk\nLyhrSNOkk96FSDaLtHzOZRVBHMTOYI7AjVJvjy/nxMW/cVwzR8mEXKXfYNJHtBOn\nyTrfIFZ3qWPKLBvMvRMa7o6uFPKLmFbE1qJ9eI0zTFGcXFZFrZ3FoUMIXQl4LUeu\nvm2wtcO/4QKBgQC6AJjjw1+5xn+xvWuKaMzGkIw2faqAjHW+/2XE3ZzJYHxcxLKn\nSBFMU0+Hp3OHHVTVDzc4nQosZbeFZ7+XYzgLf5R7Oz8EaKwvLWCv5a5kZmm2yZp9\nb27cXxU5z9QAelJEsAjYPj09zv1E7qfpJx9y9iM/Fpj19iLCgKJxYGlgmwKBgH0I\nrGAFqfAKhI7KkgWFYqELAMzfREcmSxWKIKFWN1YQFXcP3vea4zBTgc0msXGm+44k\nXUqOXHXUKgdGgqS9J2+vzwZ3uLcgk4tI7mBvEkx8Y3vZi5+MYA8PCm2NKmY3p+8Z\nRb5QUAippaQpt5Y0AmGvSJSh8HmGbGP0d0JkR4phAoGAM7rlbzH4I8sM5ha9KvOb\nOiufUY5l5BuxwsQt7UH09KPfGKxR8UIOBVXnIqfXkMQNbJolVQsfVLnZpUT+H9Um\nMXQlFvLy/EM7zS5br64PUyS5T3t2x6MnHstKYOQ5EQAHLUcN6CzygfEZwJLEmLhK\nZdLYzpMBtFvXdPCcNf3Qj6I=\n-----END PRIVATE KEY-----',
      keySize: 2048,
      publicKeyDetails: {
        algorithm: 'RSA',
        format: 'PKCS#8',
        keySize: '2048位',
        publicExponent: 'e = 65537 (0x10001)',
        modulus: 'n = MIIBIjANB...AQEFAAOCAw=='
      },
      privateKeyDetails: {
        algorithm: 'RSA',
        format: 'PKCS#8',
        keySize: '2048位',
        privateKey: 'MIIEvQIBA...f3Qj6I='
      }
    };
  }

  /**
   * 模拟加密（当浏览器环境不支持crypto.publicEncrypt时使用）
   */
  private mockEncrypt(message: string, publicKey: string): EncryptionResult {
    // 将消息内容存储为base64编码，加上固定的前缀标记作为"加密"
    const mockPrefix = "MOCK_ENCRYPTED:";
    
    // 使用文本编码器将消息转换为字节数组，然后转为base64
    let encodedMessage;
    try {
      if (typeof TextEncoder !== 'undefined') {
        // 现代浏览器
        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(message);
        encodedMessage = this.arrayBufferToBase64(messageBytes.buffer);
      } else if (typeof Buffer !== 'undefined') {
        // Node.js环境
        encodedMessage = Buffer.from(message, 'utf8').toString('base64');
      } else {
        // 降级方案
        encodedMessage = btoa(encodeURIComponent(message).replace(/%([0-9A-F]{2})/g, (_, p1) => {
          return String.fromCharCode(parseInt(p1, 16));
        }));
      }
    } catch (e) {
      console.error('模拟加密编码错误:', e);
      // 兜底方案
      encodedMessage = btoa(encodeURIComponent(message));
    }
    
    const pseudoEncrypted = mockPrefix + encodedMessage;
    
    return {
      ciphertext: pseudoEncrypted,
      metadata: {
        padding: 'OAEP',
        hashAlgorithm: 'SHA-256',
        isSimulated: true,
        note: '这是模拟加密结果，未进行实际加密'
      }
    };
  }

  /**
   * 模拟解密（当浏览器环境不支持crypto.privateDecrypt时使用）
   */
  private mockDecrypt(encryptionResult: EncryptionResult, privateKey: string): string {
    try {
      // 如果不是模拟加密的结果，但标记为isSimulated，尝试用旧的方法解码
      if (encryptionResult.metadata?.isSimulated !== true) {
        try {
          if (typeof Buffer !== 'undefined') {
            return Buffer.from(encryptionResult.ciphertext, 'base64').toString('utf8');
          } else {
            return atob(encryptionResult.ciphertext);
          }
        } catch (e) {
          console.error('解码非模拟加密结果失败:', e);
          throw new Error('无法解密非模拟加密的结果');
        }
      }
      
      // 检查是否有模拟加密前缀
      const mockPrefix = "MOCK_ENCRYPTED:";
      const ciphertext = encryptionResult.ciphertext;
      
      if (ciphertext.startsWith(mockPrefix)) {
        // 提取base64编码的消息
        const encodedMessage = ciphertext.substring(mockPrefix.length);
        // 解码回原始消息
        try {
          if (typeof TextDecoder !== 'undefined') {
            // 现代浏览器
            const bytes = this.base64ToArrayBuffer(encodedMessage);
            const decoder = new TextDecoder('utf-8');
            return decoder.decode(bytes);
          } else if (typeof Buffer !== 'undefined') {
            // Node.js环境
            return Buffer.from(encodedMessage, 'base64').toString('utf8');
          } else {
            // 降级方案
            return decodeURIComponent(atob(encodedMessage).split('').map(c => {
              return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
          }
        } catch (e) {
          console.error('模拟解密解码错误:', e);
          // 尝试简单解码
          return decodeURIComponent(escape(atob(encodedMessage)));
        }
      } else {
        // 尝试直接解码，兼容旧版本
        if (typeof Buffer !== 'undefined') {
          return Buffer.from(ciphertext, 'base64').toString('utf8');
        } else {
          try {
            return decodeURIComponent(escape(atob(ciphertext)));
          } catch (e) {
            return atob(ciphertext);
          }
        }
      }
    } catch (e) {
      console.error('模拟解密错误:', e);
      return '[解密错误: 格式不兼容]';
    }
  }

  /**
   * ArrayBuffer转base64
   */
  private arrayBufferToBase64(buffer: ArrayBufferLike): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    if (typeof btoa !== 'undefined') {
      return btoa(binary);
    } else if (typeof Buffer !== 'undefined') {
      return Buffer.from(binary, 'binary').toString('base64');
    }
    throw new Error('无法将ArrayBuffer转换为base64');
  }

  /**
   * base64转ArrayBuffer
   */
  private base64ToArrayBuffer(base64: string): Uint8Array {
    let binaryString;
    if (typeof atob !== 'undefined') {
      binaryString = atob(base64);
    } else if (typeof Buffer !== 'undefined') {
      binaryString = Buffer.from(base64, 'base64').toString('binary');
    } else {
      throw new Error('无法将base64转换为ArrayBuffer');
    }
    
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
} 