import { KeyPair, EncryptionResult, EncryptionAlgorithm } from './encryption-types';

/**
 * ElGamal加密算法实现类
 * 基于离散对数难题
 * 自主实现，减少对内置API的依赖
 */
export class ElGamalEncryption implements EncryptionAlgorithm {
  name = 'ElGamal';
  description = 'ElGamal是一种基于离散对数问题的非对称加密算法，由Taher Elgamal在1985年提出。它不仅可用于加密，还可用于数字签名。';

  // 大素数p和生成元g
  private BIG_PRIME = BigInt('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF');
  private GENERATOR = BigInt(2);

  // 用于散列的常量
  private readonly HASH_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

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
      throw new Error('ElGamal密钥生成失败');
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

      // 选择一个随机数k (临时密钥)
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
      throw new Error('ElGamal加密失败');
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
      throw new Error('ElGamal解密失败');
    }
  }

  /**
   * 大数据分块加密
   */
  private async blockEncrypt(message: string, publicKey: any): Promise<EncryptionResult> {
    const { p } = publicKey;
    const P = BigInt(p);
    
    // 计算每个块的大小（以字节为单位）
    // 每个块的大小应该比p小，确保可以被加密
    const blockSize = Math.floor((P.toString().length - 1) / 4);
    
    // 将消息转换为字节数组
    const messageBytes = this.stringToBytes(message);
    const blocks: Uint8Array[] = [];
    
    // 将消息分割成块
    for (let i = 0; i < messageBytes.length; i += blockSize) {
      blocks.push(messageBytes.slice(i, Math.min(i + blockSize, messageBytes.length)));
    }
    
    // 加密每个块
    const encryptedBlocks = [];
    for (const block of blocks) {
      const blockMessage = this.bytesToString(block);
      const blockResult = await this.encrypt(blockMessage, publicKey);
      encryptedBlocks.push(JSON.parse(blockResult.ciphertext));
    }
    
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
    let decryptedText = '';
    
    // 解密每个块
    for (const block of encryptedBlocks) {
      const blockResult: EncryptionResult = {
        ciphertext: JSON.stringify(block)
      };
      
      decryptedText += await this.decrypt(blockResult, privateKey);
    }
    
    return decryptedText;
  }

  /**
   * 快速模幂算法计算 base^exponent mod modulus
   * @param base 底数
   * @param exponent 指数
   * @param modulus 模数
   * @returns 模幂结果
   */
  private modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === 1n) return 0n;
    
    let result = 1n;
    base = base % modulus;
    
    while (exponent > 0n) {
      // 如果指数的当前位为1，将当前的base值乘到结果中
      if (exponent % 2n === 1n) {
        result = (result * base) % modulus;
      }
      
      // 平方底数，并右移指数
      exponent = exponent >> 1n;
      base = (base * base) % modulus;
    }
    
    return result;
  }

  /**
   * 计算模逆元：a^(-1) mod m，使得a * a^(-1) ≡ 1 (mod m)
   * 使用扩展欧几里得算法
   * @param a 要求逆元的数
   * @param m 模数
   * @returns 模逆元
   */
  private modInverse(a: bigint, m: bigint): bigint {
    if (m === 1n) return 0n;
    
    // 确保a为正
    a = ((a % m) + m) % m;
    
    // 扩展欧几里得算法
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    
    while (r !== 0n) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
    }
    
    // 检查GCD是否为1
    if (old_r !== 1n) {
      throw new Error(`模逆元不存在. GCD(${a}, ${m}) = ${old_r}`);
    }
    
    // 确保结果为正
    return (old_s % m + m) % m;
  }

  /**
   * 生成指定范围内的随机大整数
   * @param max 最大值（不包含）
   * @returns 随机大整数
   */
  private generateRandomBigInt(max: bigint): bigint {
    const bitLength = this.getBitLength(max);
    let result: bigint;
    
    do {
      // 生成随机字节数组
      const byteLength = Math.ceil(bitLength / 8);
      const randomBytes = this.getRandomBytes(byteLength);
      
      // 转换为BigInt
      result = this.bytesToBigInt(randomBytes);
      
      // 确保结果小于max
      result = result % max;
    } while (result <= 0n);
    
    return result;
  }

  /**
   * 将文本转换为BigInt
   * @param text 文本
   * @returns BigInt值
   */
  private textToBigInt(text: string): bigint {
    const bytes = this.stringToBytes(text);
    return this.bytesToBigInt(bytes);
  }

  /**
   * 将BigInt转换为文本
   * @param value BigInt值
   * @returns 文本
   */
  private bigIntToText(value: bigint): string {
    const bytes: number[] = [];
    let temp = value;
    
    while (temp > 0n) {
      bytes.unshift(Number(temp & 0xFFn));
      temp = temp >> 8n;
    }
    
    return this.bytesToString(new Uint8Array(bytes));
  }

  /**
   * 将字符串转换为字节数组
   * @param str 字符串
   * @returns 字节数组
   */
  private stringToBytes(str: string): Uint8Array {
    if (typeof TextEncoder !== 'undefined') {
      return new TextEncoder().encode(str);
    } else {
      // 简单实现，适用于ASCII字符
      const bytes = new Uint8Array(str.length);
      for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i) & 0xff;
      }
      return bytes;
    }
  }

  /**
   * 将字节数组转换为字符串
   * @param bytes 字节数组
   * @returns 字符串
   */
  private bytesToString(bytes: Uint8Array): string {
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder().decode(bytes);
    } else {
      // 简单实现，适用于ASCII字符
      return Array.from(bytes).map(byte => String.fromCharCode(byte)).join('');
    }
  }

  /**
   * 将字节数组转换为BigInt
   * @param bytes 字节数组
   * @returns BigInt值
   */
  private bytesToBigInt(bytes: Uint8Array): bigint {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
      result = (result << 8n) | BigInt(bytes[i]);
    }
    return result;
  }

  /**
   * 将BigInt转换为字节数组
   * @param value BigInt值
   * @param length 字节数组长度（可选）
   * @returns 字节数组
   */
  private bigIntToBytes(value: bigint, length?: number): Uint8Array {
    const bytes: number[] = [];
    let temp = value;
    
    while (temp > 0n) {
      bytes.unshift(Number(temp & 0xFFn));
      temp = temp >> 8n;
    }
    
    // 如果指定了长度，填充0确保长度正确
    if (length !== undefined) {
      while (bytes.length < length) {
        bytes.unshift(0);
      }
    }
    
    return new Uint8Array(bytes);
  }

  /**
   * 获取大整数的位长度
   * @param n 大整数
   * @returns 位长度
   */
  private getBitLength(n: bigint): number {
    return n.toString(2).length;
  }

  /**
   * 生成指定长度的随机字节数组
   * @param length 字节长度
   * @returns 随机字节数组
   */
  private getRandomBytes(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    
    if (typeof window !== 'undefined' && window.crypto) {
      window.crypto.getRandomValues(bytes);
    } else {
      // 如果不是浏览器环境，使用自定义的伪随机数填充
      for (let i = 0; i < length; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    
    return bytes;
  }

  /**
   * 缩写字符串，用于显示长数字
   * @param str 字符串
   * @returns 缩写后的字符串
   */
  private abbreviateString(str: string): string {
    if (str.length <= 10) return str;
    return `${str.substring(0, 4)}...${str.substring(str.length - 4)}`;
  }

  /**
   * 简单哈希函数（简化版SHA-256）
   * @param data 要哈希的数据
   * @returns 哈希值
   */
  private simpleHash(data: Uint8Array): Uint8Array {
    // 使用初始哈希值
    let h = [...this.HASH_INIT];
    
    // 简化版哈希计算
    for (let i = 0; i < data.length; i++) {
      const byte = data[i];
      for (let j = 0; j < 8; j++) {
        h[j] = ((h[j] << 5) - h[j] + byte) | 0;
      }
    }
    
    // 转换为字节数组
    const result = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      for (let j = 0; j < 4; j++) {
        result[i * 4 + j] = (h[i] >>> ((3 - j) * 8)) & 0xff;
      }
    }
    
    return result;
  }
} 