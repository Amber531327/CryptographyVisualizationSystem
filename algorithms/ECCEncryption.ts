import { KeyPair, EncryptionResult, EncryptionAlgorithm } from './encryption-types';
import * as crypto from 'crypto';

/**
 * 椭圆曲线加密算法实现类
 * 基于椭圆曲线离散对数问题
 */
export class ECCEncryption implements EncryptionAlgorithm {
  name = 'ECC';
  description = 'ECC(椭圆曲线密码学)是一种基于椭圆曲线数学的非对称加密算法，相比传统的RSA算法，ECC可以使用更短的密钥提供相同级别的安全性。';
  
  // 使用P-256曲线作为默认曲线
  private curveName = 'prime256v1'; // 也称为P-256或secp256r1
  
  /**
   * 生成ECC密钥对
   * @returns 包含公钥和私钥的KeyPair对象
   */
  async generateKeys(): Promise<KeyPair> {
    try {
      // 在Node.js环境中生成ECDH密钥对
      const ecdh = crypto.createECDH(this.curveName);
      ecdh.generateKeys();
      
      const privateKey = ecdh.getPrivateKey().toString('hex');
      const publicKey = ecdh.getPublicKey().toString('hex');
      
      return {
        publicKey: {
          key: publicKey,
          curve: this.curveName
        },
        privateKey: {
          key: privateKey,
          curve: this.curveName
        },
        keySize: 256, // P-256曲线使用256位密钥
        publicKeyDetails: {
          algorithm: 'ECC',
          curve: this.curveName,
          keySize: '256位',
          publicKey: this.abbreviateString(publicKey)
        },
        privateKeyDetails: {
          algorithm: 'ECC',
          curve: this.curveName,
          keySize: '256位',
          privateKey: this.abbreviateString(privateKey)
        }
      };
    } catch (error) {
      console.error('ECC密钥生成错误:', error);
      // 如果在浏览器环境中无法使用crypto.createECDH，提供模拟密钥
      return this.generateMockKeys();
    }
  }

  /**
   * 使用ECIES（椭圆曲线集成加密方案）进行加密
   * @param message 要加密的明文消息
   * @param publicKey 接收方的公钥
   * @returns 包含密文的加密结果
   */
  async encrypt(message: string, publicKey: any): Promise<EncryptionResult> {
    try {
      // 创建临时的ECDH密钥对
      const ephemeral = crypto.createECDH(publicKey.curve);
      ephemeral.generateKeys();
      
      // 将接收方的公钥转换为Buffer
      const recipientPubKey = Buffer.from(publicKey.key, 'hex');
      
      // 计算共享密钥
      const sharedSecret = ephemeral.computeSecret(recipientPubKey);
      
      // 使用共享密钥派生对称加密密钥
      const encryptionKey = crypto.createHash('sha256').update(sharedSecret).digest();
      
      // 生成随机IV
      const iv = crypto.randomBytes(16);
      
      // 使用AES-256-CBC加密消息
      const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
      let encrypted = cipher.update(message, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      
      return {
        ciphertext: encrypted,
        ephemeralKey: ephemeral.getPublicKey().toString('hex'),
        iv: iv.toString('hex'),
        metadata: {
          curve: publicKey.curve,
          algorithm: 'ECIES',
          kdf: 'SHA-256',
          cipher: 'AES-256-CBC'
        }
      };
    } catch (error) {
      console.error('ECC加密错误:', error);
      // 如果无法使用Node.js的加密API，使用模拟加密
      return this.mockEncrypt(message);
    }
  }

  /**
   * 使用ECIES解密消息
   * @param encryptionResult 包含密文的加密结果
   * @param privateKey 接收方的私钥
   * @returns 解密后的明文
   */
  async decrypt(encryptionResult: EncryptionResult, privateKey: any): Promise<string> {
    try {
      // 创建ECDH实例并设置私钥
      const ecdh = crypto.createECDH(privateKey.curve);
      ecdh.setPrivateKey(Buffer.from(privateKey.key, 'hex'));
      
      // 获取对方的临时公钥
      if (!encryptionResult.ephemeralKey) {
        throw new Error('缺少临时公钥');
      }
      const ephemeralPubKey = Buffer.from(encryptionResult.ephemeralKey, 'hex');
      
      // 计算共享密钥
      const sharedSecret = ecdh.computeSecret(ephemeralPubKey);
      
      // 使用共享密钥派生对称解密密钥
      const decryptionKey = crypto.createHash('sha256').update(sharedSecret).digest();
      
      // 获取IV
      if (!encryptionResult.iv) {
        throw new Error('缺少初始化向量');
      }
      const iv = Buffer.from(encryptionResult.iv, 'hex');
      
      // 使用AES-256-CBC解密消息
      const decipher = crypto.createDecipheriv('aes-256-cbc', decryptionKey, iv);
      let decrypted = decipher.update(encryptionResult.ciphertext, 'base64', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      console.error('ECC解密错误:', error);
      // 如果无法正常解密，返回错误提示
      return '[解密错误]';
    }
  }

  /**
   * 缩短字符串用于显示
   */
  private abbreviateString(str: string): string {
    if (str.length <= 20) return str;
    return str.substring(0, 10) + '...' + str.substring(str.length - 10);
  }

  /**
   * 生成模拟密钥（当环境不支持crypto.createECDH时使用）
   */
  private generateMockKeys(): KeyPair {
    return {
      publicKey: {
        key: '04a5b8d3f97b5a6c4b542e8475f16a5d9ae878c5b2da40961518dc2a94272bf1d0c9b857d7b8c18bbecad98f1f0c3c3e9ec97c85e19812f71b13d2af7689d5837e',
        curve: this.curveName
      },
      privateKey: {
        key: '7d4d26a80459304ad80cb8a88583719f17dd4e22376b2c2d7a8ce77044787260',
        curve: this.curveName
      },
      keySize: 256,
      publicKeyDetails: {
        algorithm: 'ECC',
        curve: this.curveName,
        keySize: '256位',
        publicKey: '04a5b8d3f9...9d5837e'
      },
      privateKeyDetails: {
        algorithm: 'ECC',
        curve: this.curveName,
        keySize: '256位',
        privateKey: '7d4d26a804...4787260'
      }
    };
  }

  /**
   * 模拟加密（当无法使用正常加密时）
   */
  private mockEncrypt(message: string): EncryptionResult {
    // 简单地使用Base64编码"加密"，仅用于演示
    const mockCiphertext = Buffer.from(message).toString('base64');
    
    return {
      ciphertext: mockCiphertext,
      ephemeralKey: '04c6fc1c9470c00dc9ef4c2951a992eee7237372fa2d4cbce4fe4c89f3346195d94440453b0bfebe3c2f790268f70a065d59f7c29a5777b6eb886c1b0c71d383a7',
      iv: 'd3a7970f650d0a4feb15ab43cef3d245',
      metadata: {
        curve: this.curveName,
        algorithm: 'ECIES (模拟)',
        note: '这是模拟加密结果，仅用于演示'
      }
    };
  }
} 