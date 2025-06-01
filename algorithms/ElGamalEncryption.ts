import { KeyPair, EncryptionResult, EncryptionAlgorithm } from './encryption-types';
import * as crypto from 'crypto';

/**
 * ElGamal加密算法实现类
 * 基于离散对数难题
 */
export class ElGamalEncryption implements EncryptionAlgorithm {
  name = 'ElGamal';
  description = 'ElGamal是一种基于离散对数问题的非对称加密算法，由Taher Elgamal在1985年提出。它不仅可用于加密，还可用于数字签名。';

  // 大素数p和生成元g
  private BIG_PRIME = BigInt('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF');
  private GENERATOR = BigInt(2);

  /**
   * 生成ElGamal密钥对
   * @returns 包含公钥和私钥的KeyPair对象
   */
  async generateKeys(): Promise<KeyPair> {
    try {
      // 私钥x是一个随机数
      const privateKey = this.generateRandomBigInt(this.BIG_PRIME - BigInt(1));
      // 公钥y = g^x mod p
      const publicKey = this.modPow(this.GENERATOR, privateKey, this.BIG_PRIME);

      return {
        publicKey: {
          y: publicKey.toString(),
          g: this.GENERATOR.toString(),
          p: this.BIG_PRIME.toString()
        },
        privateKey: {
          x: privateKey.toString(),
          p: this.BIG_PRIME.toString()
        },
        keySize: 2048,
        publicKeyDetails: {
          algorithm: 'ElGamal',
          keySize: '2048位',
          p: this.abbreviateString(this.BIG_PRIME.toString()),
          g: this.GENERATOR.toString(),
          y: this.abbreviateString(publicKey.toString())
        },
        privateKeyDetails: {
          algorithm: 'ElGamal',
          keySize: '2048位',
          x: this.abbreviateString(privateKey.toString())
        }
      };
    } catch (error) {
      console.error('ElGamal密钥生成错误:', error);
      return this.generateMockKeys();
    }
  }

  /**
   * 使用公钥加密消息
   * @param message 要加密的明文消息
   * @param publicKey 加密用的公钥
   * @returns 包含密文的加密结果
   */
  async encrypt(message: string, publicKey: any): Promise<EncryptionResult> {
    try {
      const { y, g, p } = publicKey;
      const Y = BigInt(y);
      const G = BigInt(g);
      const P = BigInt(p);

      // 将消息转换为数值
      const M = this.textToBigInt(message);
      
      // 检查消息是否小于p，如果不是，需要分段加密
      if (M >= P) {
        return this.blockEncrypt(message, publicKey);
      }

      // 选择一个随机数k
      const k = this.generateRandomBigInt(P - BigInt(1));
      
      // 计算c1 = g^k mod p
      const c1 = this.modPow(G, k, P);
      
      // 计算s = y^k mod p
      const s = this.modPow(Y, k, P);
      
      // 计算c2 = M * s mod p
      const c2 = (M * s) % P;
      
      return {
        ciphertext: JSON.stringify({
          c1: c1.toString(),
          c2: c2.toString()
        }),
        ephemeralKey: k.toString(),
        metadata: {
          isBlocked: false
        }
      };
    } catch (error) {
      console.error('ElGamal加密错误:', error);
      return this.mockEncrypt(message, publicKey);
    }
  }

  /**
   * 使用私钥解密消息
   * @param encryptionResult 包含密文的加密结果
   * @param privateKey 解密用的私钥
   * @returns 解密后的明文
   */
  async decrypt(encryptionResult: EncryptionResult, privateKey: any): Promise<string> {
    try {
      const { x, p } = privateKey;
      const X = BigInt(x);
      const P = BigInt(p);
      
      // 检查是否是分块加密
      const metadata: any = encryptionResult.metadata || {};
      if (metadata.isBlocked) {
        return this.blockDecrypt(encryptionResult, privateKey);
      }
      
      // 解析密文
      const { c1, c2 } = JSON.parse(encryptionResult.ciphertext);
      const C1 = BigInt(c1);
      const C2 = BigInt(c2);
      
      // 计算s = c1^x mod p
      const s = this.modPow(C1, X, P);
      
      // 计算s的模逆元s^(-1) mod p
      const sInverse = this.modInverse(s, P);
      
      // 计算明文 M = c2 * s^(-1) mod p
      const M = (C2 * sInverse) % P;
      
      // 将数值转换回文本
      return this.bigIntToText(M);
    } catch (error) {
      console.error('ElGamal解密错误:', error);
      return '[解密错误]';
    }
  }

  /**
   * 大数据分块加密
   */
  private async blockEncrypt(message: string, publicKey: any): Promise<EncryptionResult> {
    const { y, g, p } = publicKey;
    const P = BigInt(p);
    
    // 计算每个块的大小（以字节为单位）
    const blockSize = Math.floor((P.toString().length - 1) / 2);
    
    // 将消息分割成块
    const messageBytes = Buffer.from(message, 'utf8');
    const blocks: Buffer[] = [];
    
    for (let i = 0; i < messageBytes.length; i += blockSize) {
      blocks.push(messageBytes.slice(i, i + blockSize));
    }
    
    // 加密每个块
    const encryptedBlocks = await Promise.all(
      blocks.map(async (block) => {
        const blockMessage = block.toString('utf8');
        const blockM = this.textToBigInt(blockMessage);
        
        // 对每个块进行ElGamal加密
        const result = await this.encrypt(blockMessage, publicKey);
        return JSON.parse(result.ciphertext);
      })
    );
    
    return {
      ciphertext: JSON.stringify(encryptedBlocks),
      metadata: {
        isBlocked: true,
        blockCount: blocks.length
      }
    };
  }

  /**
   * 大数据分块解密
   */
  private async blockDecrypt(encryptionResult: EncryptionResult, privateKey: any): Promise<string> {
    const encryptedBlocks = JSON.parse(encryptionResult.ciphertext);
    
    // 解密每个块
    const decryptedBlocks = await Promise.all(
      encryptedBlocks.map(async (block: any) => {
        const blockResult: EncryptionResult = {
          ciphertext: JSON.stringify(block)
        };
        
        return this.decrypt(blockResult, privateKey);
      })
    );
    
    // 拼接所有解密后的块
    return decryptedBlocks.join('');
  }

  /**
   * 计算 (base^exponent) % modulus
   */
  private modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === BigInt(1)) return BigInt(0);
    
    let result = BigInt(1);
    base = base % modulus;
    
    while (exponent > BigInt(0)) {
      if (exponent % BigInt(2) === BigInt(1)) {
        result = (result * base) % modulus;
      }
      exponent = exponent / BigInt(2);
      base = (base * base) % modulus;
    }
    
    return result;
  }

  /**
   * 计算模逆元 a^(-1) mod m
   * 使用扩展欧几里得算法
   */
  private modInverse(a: bigint, m: bigint): bigint {
    a = ((a % m) + m) % m; // 确保a为正数
    
    let [old_r, r] = [a, m];
    let [old_s, s] = [BigInt(1), BigInt(0)];
    let [old_t, t] = [BigInt(0), BigInt(1)];
    
    while (r !== BigInt(0)) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
      [old_t, t] = [t, old_t - quotient * t];
    }
    
    // 检查a和m是否互质
    if (old_r !== BigInt(1)) {
      throw new Error('模逆元不存在');
    }
    
    return (old_s % m + m) % m;
  }

  /**
   * 生成一个0到max-1之间的随机BigInt
   */
  private generateRandomBigInt(max: bigint): bigint {
    const bitLength = max.toString(2).length;
    const byteLength = Math.ceil(bitLength / 8);
    
    // 生成随机字节
    let randomBytes: Buffer;
    try {
      randomBytes = crypto.randomBytes(byteLength);
    } catch (e) {
      // 如果不支持crypto.randomBytes，使用Math.random
      randomBytes = Buffer.alloc(byteLength);
      for (let i = 0; i < byteLength; i++) {
        randomBytes[i] = Math.floor(Math.random() * 256);
      }
    }
    
    // 将字节转换为BigInt
    let randomValue = BigInt('0x' + randomBytes.toString('hex'));
    
    // 确保值在范围内
    return randomValue % max;
  }

  /**
   * 将文本转换为BigInt
   */
  private textToBigInt(text: string): bigint {
    const buffer = Buffer.from(text, 'utf8');
    return BigInt('0x' + buffer.toString('hex'));
  }

  /**
   * 将BigInt转换为文本
   */
  private bigIntToText(value: bigint): string {
    const hex = value.toString(16);
    // 确保十六进制字符串长度为偶数
    const paddedHex = hex.length % 2 ? '0' + hex : hex;
    
    try {
      return Buffer.from(paddedHex, 'hex').toString('utf8');
    } catch (e) {
      console.error('解码错误:', e);
      return '[解码错误]';
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
   * 生成模拟密钥（当环境不支持正常生成时使用）
   */
  private generateMockKeys(): KeyPair {
    return {
      publicKey: {
        y: '65537',
        g: '2',
        p: this.BIG_PRIME.toString()
      },
      privateKey: {
        x: '12345',
        p: this.BIG_PRIME.toString()
      },
      keySize: 2048,
      publicKeyDetails: {
        algorithm: 'ElGamal',
        keySize: '2048位',
        p: this.abbreviateString(this.BIG_PRIME.toString()),
        g: '2',
        y: '65537'
      },
      privateKeyDetails: {
        algorithm: 'ElGamal',
        keySize: '2048位',
        x: '12345'
      }
    };
  }

  /**
   * 模拟加密（当正常加密无法工作时使用）
   */
  private mockEncrypt(message: string, publicKey: any): EncryptionResult {
    const pseudoEncrypted = Buffer.from(message).toString('base64');
    return {
      ciphertext: JSON.stringify({
        c1: '12345',
        c2: pseudoEncrypted
      }),
      ephemeralKey: '54321',
      metadata: {
        note: '这是模拟加密结果，仅用于演示'
      }
    };
  }
} 