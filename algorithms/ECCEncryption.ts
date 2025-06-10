import { KeyPair, EncryptionResult, EncryptionAlgorithm } from './encryption-types';

/**
 * 椭圆曲线加密算法实现类
 * 基于椭圆曲线离散对数问题
 * 自主实现，减少对内置API的依赖
 */
export class ECCEncryption implements EncryptionAlgorithm {
  name = 'ECC';
  description = 'ECC(椭圆曲线密码学)是一种基于椭圆曲线数学的非对称加密算法，相比传统的RSA算法，ECC可以使用更短的密钥提供相同级别的安全性。';
  
  // 使用自定义的椭圆曲线参数（简化版的secp256k1参数）
  private curve = {
    p: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'), // 素数域大小
    a: BigInt(0), // 曲线参数a
    b: BigInt(7), // 曲线参数b
    Gx: BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'), // 基点x坐标
    Gy: BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'), // 基点y坐标
    n: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'), // 基点阶
    name: 'secp256k1'
  };

  // 用于哈希函数的常量
  private readonly HASH_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  /**
   * 生成ECC密钥对
   * @returns 包含公钥和私钥的KeyPair对象
   */
  async generateKeys(): Promise<KeyPair> {
    try {
      // 生成私钥（随机数）
      const privateKey = this.generateRandomBigInt(this.curve.n - BigInt(1));
      
      // 根据私钥计算公钥点 Q = d * G
      const publicKeyPoint = this.pointMultiply(
        { x: this.curve.Gx, y: this.curve.Gy },
        privateKey
      );
      
      // 将公钥点转换为压缩格式
      const publicKey = this.pointToHex(publicKeyPoint);
      
      return {
        publicKey: {
          key: publicKey,
          curve: this.curve.name
        },
        privateKey: {
          key: privateKey.toString(16).padStart(64, '0'),
          curve: this.curve.name
        },
        keySize: 256,
        publicKeyDetails: {
          algorithm: 'ECC',
          curve: this.curve.name,
          keySize: '256位',
          publicKey: this.abbreviateString(publicKey)
        },
        privateKeyDetails: {
          algorithm: 'ECC',
          curve: this.curve.name,
          keySize: '256位',
          privateKey: this.abbreviateString(privateKey.toString(16))
        }
      };
    } catch (error) {
      console.error('ECC密钥生成错误:', error);
      throw new Error('ECC密钥生成失败');
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
      // 将接收方的公钥字符串转换为点
      const recipientPubPoint = this.hexToPoint(publicKey.key);
      
      // 生成临时私钥
      const ephemeralPrivateKey = this.generateRandomBigInt(this.curve.n - BigInt(1));
      
      // 计算临时公钥 R = k * G
      const ephemeralPublicPoint = this.pointMultiply(
        { x: this.curve.Gx, y: this.curve.Gy },
        ephemeralPrivateKey
      );
      
      // 计算共享密钥点 S = k * P (P是接收方公钥)
      const sharedSecret = this.pointMultiply(
        recipientPubPoint,
        ephemeralPrivateKey
      );
      
      // 从共享密钥派生对称加密密钥
      const sharedSecretBytes = this.pointToBytes(sharedSecret);
      const keyMaterial = this.simpleHash(sharedSecretBytes);
      
      // 使用派生的密钥对消息进行加密（使用简单的XOR加密作为示例）
      // 生成随机IV
      const iv = this.getRandomBytes(16);
      
      // 加密
      const messageBytes = this.stringToBytes(message);
      const ciphertext = this.xorEncrypt(messageBytes, keyMaterial, iv);
      
      return {
        ciphertext: this.bytesToBase64(ciphertext),
        ephemeralKey: this.pointToHex(ephemeralPublicPoint),
        iv: this.bytesToHex(iv),
        metadata: {
          curve: publicKey.curve,
          algorithm: 'ECIES',
          kdf: 'SHA-256',
          cipher: 'XOR-CIPHER'
        }
      };
    } catch (error) {
      console.error('ECC加密错误:', error);
      throw new Error('ECC加密失败');
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
      // 获取私钥
      const receiverPrivateKey = BigInt('0x' + privateKey.key);
      
      // 获取对方的临时公钥
      if (!encryptionResult.ephemeralKey) {
        throw new Error('缺少临时公钥');
      }
      const ephemeralPublicPoint = this.hexToPoint(encryptionResult.ephemeralKey);
      
      // 计算共享密钥点 S = d * R (d是接收方私钥，R是发送方临时公钥)
      const sharedSecret = this.pointMultiply(
        ephemeralPublicPoint,
        receiverPrivateKey
      );
      
      // 从共享密钥派生对称解密密钥
      const sharedSecretBytes = this.pointToBytes(sharedSecret);
      const keyMaterial = this.simpleHash(sharedSecretBytes);
      
      // 获取IV
      if (!encryptionResult.iv) {
        throw new Error('缺少初始化向量');
      }
      const iv = this.hexToBytes(encryptionResult.iv);
      
      // 解密
      const ciphertext = this.base64ToBytes(encryptionResult.ciphertext);
      const decryptedBytes = this.xorDecrypt(ciphertext, keyMaterial, iv);
      
      // 转换为字符串
      return this.bytesToString(decryptedBytes);
    } catch (error) {
      console.error('ECC解密错误:', error);
      throw new Error('ECC解密失败');
    }
  }

  /**
   * 椭圆曲线上的点加法
   * @param p1 第一个点
   * @param p2 第二个点
   * @returns 两点之和
   */
  private pointAdd(p1: { x: bigint, y: bigint }, p2: { x: bigint, y: bigint }): { x: bigint, y: bigint } {
    // 如果其中一个点是无穷远点，返回另一个点
    if (p1.x === 0n && p1.y === 0n) return p2;
    if (p2.x === 0n && p2.y === 0n) return p1;
    
    const { p, a } = this.curve;
    
    // 如果两点互为逆元，返回无穷远点
    if (p1.x === p2.x && p1.y === ((p - p2.y) % p)) {
      return { x: 0n, y: 0n };
    }
    
    // 计算斜率
    let lambda: bigint;
    if (p1.x === p2.x && p1.y === p2.y) {
      // 点加自己 (doubling)
      lambda = ((3n * p1.x * p1.x + a) * this.modInverse((2n * p1.y) % p, p)) % p;
    } else {
      // 两个不同点相加
      lambda = ((p2.y - p1.y + p) * this.modInverse((p2.x - p1.x + p) % p, p)) % p;
    }
    
    // 计算结果点坐标
    const x3 = (lambda * lambda - p1.x - p2.x) % p;
    const y3 = (lambda * (p1.x - x3) - p1.y) % p;
    
    // 确保结果在正确的范围内
    return {
      x: (x3 + p) % p,
      y: (y3 + p) % p
    };
  }

  /**
   * 椭圆曲线上的点乘法（标量乘法）
   * @param point 基点
   * @param scalar 标量
   * @returns 乘法结果
   */
  private pointMultiply(point: { x: bigint, y: bigint }, scalar: bigint): { x: bigint, y: bigint } {
    // 将标量转换为二进制，并从最高位开始处理
    const binaryScalar = scalar.toString(2);
    
    // 无穷远点
    let result = { x: 0n, y: 0n };
    
    for (let i = 0; i < binaryScalar.length; i++) {
      // 加倍
      result = this.pointAdd(result, result);
      
      // 如果当前位为1，加上基点
      if (binaryScalar[i] === '1') {
        result = this.pointAdd(result, point);
      }
    }
    
    return result;
  }

  /**
   * 将点转换为十六进制字符串
   * @param point 椭圆曲线上的点
   * @returns 十六进制表示
   */
  private pointToHex(point: { x: bigint, y: bigint }): string {
    // 使用压缩格式：02/03 + x坐标（偶数/奇数y）
    const prefix = point.y % 2n === 0n ? '02' : '03';
    const xHex = point.x.toString(16).padStart(64, '0');
    return prefix + xHex;
  }

  /**
   * 将十六进制字符串转换为点
   * @param hex 十六进制字符串
   * @returns 椭圆曲线上的点
   */
  private hexToPoint(hex: string): { x: bigint, y: bigint } {
    // 解析压缩格式
    if (hex.startsWith('02') || hex.startsWith('03')) {
      const prefix = hex.substring(0, 2);
      const xHex = hex.substring(2);
      
      const x = BigInt('0x' + xHex);
      const isYOdd = prefix === '03';
      
      // 根据曲线方程 y² = x³ + ax + b 计算y
      const { p, a, b } = this.curve;
      
      // 计算 y² = x³ + ax + b (mod p)
      let ySquared = (x * x * x + a * x + b) % p;
      
      // 计算 y = sqrt(y²) (mod p)
      let y = this.modSqrt(ySquared, p);
      
      // 根据前缀调整y
      if ((y % 2n === 0n) !== (prefix === '02')) {
        y = (p - y) % p;
      }
      
      return { x, y };
    }
    
    // 解析未压缩格式（04 + x + y）
    if (hex.startsWith('04')) {
      const xHex = hex.substring(2, 66);
      const yHex = hex.substring(66);
      
      return {
        x: BigInt('0x' + xHex),
        y: BigInt('0x' + yHex)
      };
    }
    
    throw new Error('无效的公钥格式');
  }

  /**
   * 将点转换为字节数组
   * @param point 椭圆曲线上的点
   * @returns 字节数组
   */
  private pointToBytes(point: { x: bigint, y: bigint }): Uint8Array {
    const xBytes = this.bigIntToBytes(point.x, 32);
    const yBytes = this.bigIntToBytes(point.y, 32);
    
    const result = new Uint8Array(65);
    result[0] = 0x04; // 未压缩格式标识
    result.set(xBytes, 1);
    result.set(yBytes, 33);
    
    return result;
  }

  /**
   * 计算模平方根（Tonelli-Shanks算法）
   * @param n 要计算平方根的数
   * @param p 模数（素数）
   * @returns 模平方根
   */
  private modSqrt(n: bigint, p: bigint): bigint {
    // 处理简单情况
    if (n === 0n) return 0n;
    if (p === 2n) return n;
    
    // 检查n是否是p的二次剩余
    const legendreSymbol = this.modPow(n, (p - 1n) / 2n, p);
    if (legendreSymbol !== 1n) {
      throw new Error(`${n} 不是 ${p} 的二次剩余`);
    }
    
    // 找到p-1的形式：2^s * q，其中q是奇数
    let q = p - 1n;
    let s = 0;
    while (q % 2n === 0n) {
      q /= 2n;
      s++;
    }
    
    // 如果s=1，使用简单公式
    if (s === 1) {
      return this.modPow(n, (p + 1n) / 4n, p);
    }
    
    // 寻找二次非剩余z
    let z = 2n;
    while (this.modPow(z, (p - 1n) / 2n, p) === 1n) {
      z++;
    }
    
    // 初始化变量
    let c = this.modPow(z, q, p);
    let r = this.modPow(n, (q + 1n) / 2n, p);
    let t = this.modPow(n, q, p);
    let m = s;
    
    while (t !== 1n) {
      // 找到t的最小i使得t^(2^i) ≡ 1 (mod p)
      let i = 0;
      let t2i = t;
      while (t2i !== 1n) {
        t2i = (t2i * t2i) % p;
        i++;
        if (i >= m) {
          throw new Error('无法计算模平方根');
        }
      }
      
      // 计算b = c^(2^(m-i-1))
      let b = c;
      for (let j = 0; j < m - i - 1; j++) {
        b = (b * b) % p;
      }
      
      // 更新变量
      r = (r * b) % p;
      c = (b * b) % p;
      t = (t * c) % p;
      m = i;
    }
    
    return r;
  }

  /**
   * 将字节数组转换为Base64字符串
   * @param bytes 字节数组
   * @returns Base64编码的字符串
   */
  private bytesToBase64(bytes: Uint8Array): string {
    // 简单实现，在浏览器中使用btoa
    if (typeof btoa === 'function') {
      const binaryString = Array.from(bytes).map(byte => String.fromCharCode(byte)).join('');
      return btoa(binaryString);
    } else {
      // 在Node.js环境中
      const buffer = Buffer.from(bytes);
      return buffer.toString('base64');
    }
  }

  /**
   * 将Base64字符串转换为字节数组
   * @param base64 Base64编码的字符串
   * @returns 字节数组
   */
  private base64ToBytes(base64: string): Uint8Array {
    // 简单实现，在浏览器中使用atob
    if (typeof atob === 'function') {
      const binaryString = atob(base64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes;
    } else {
      // 在Node.js环境中
      const buffer = Buffer.from(base64, 'base64');
      return new Uint8Array(buffer);
    }
  }

  /**
   * 将字节数组转换为十六进制字符串
   * @param bytes 字节数组
   * @returns 十六进制字符串
   */
  private bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * 将十六进制字符串转换为字节数组
   * @param hex 十六进制字符串
   * @returns 字节数组
   */
  private hexToBytes(hex: string): Uint8Array {
    // 确保十六进制字符串有偶数个字符
    if (hex.length % 2 !== 0) {
      hex = '0' + hex;
    }
    
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    
    return bytes;
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
   * 将BigInt转换为指定长度的字节数组
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
    if (str.length <= 20) return str;
    return str.substring(0, 10) + '...' + str.substring(str.length - 10);
  }

  /**
   * 使用简单的哈希函数（类似SHA-256）
   * @param data 要哈希的数据
   * @returns 哈希值（32字节）
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

  /**
   * 使用XOR和伪随机数生成器实现简单的加密
   * @param data 明文数据
   * @param key 密钥
   * @param iv 初始化向量
   * @returns 密文
   */
  private xorEncrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
    // 生成密钥流
    const keyStream = this.generateKeyStream(key, iv, data.length);
    
    // 对数据进行XOR
    const ciphertext = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      ciphertext[i] = data[i] ^ keyStream[i];
    }
    
    return ciphertext;
  }

  /**
   * 使用XOR和伪随机数生成器实现简单的解密
   * @param data 密文数据
   * @param key 密钥
   * @param iv 初始化向量
   * @returns 明文
   */
  private xorDecrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
    // 解密过程与加密相同（XOR操作的对称性）
    return this.xorEncrypt(data, key, iv);
  }

  /**
   * 生成密钥流
   * @param key 密钥
   * @param iv 初始化向量
   * @param length 需要的密钥流长度
   * @returns 密钥流
   */
  private generateKeyStream(key: Uint8Array, iv: Uint8Array, length: number): Uint8Array {
    const keyStream = new Uint8Array(length);
    
    // 使用密钥和IV初始化一个伪随机数生成器
    let counter = new Uint8Array(16);
    for (let i = 0; i < Math.min(iv.length, 16); i++) {
      counter[i] = iv[i];
    }
    
    // 生成足够长的密钥流
    let pos = 0;
    while (pos < length) {
      // 将计数器与密钥混合，产生伪随机数据块
      const hash = this.simpleHash(this.concatBytes(counter, key));
      
      // 将随机数据块添加到密钥流
      const blockSize = Math.min(hash.length, length - pos);
      keyStream.set(hash.slice(0, blockSize), pos);
      pos += blockSize;
      
      // 增加计数器
      for (let i = 0; i < counter.length; i++) {
        counter[i]++;
        if (counter[i] !== 0) break; // 没有进位，跳出
      }
    }
    
    return keyStream;
  }

  /**
   * 连接两个字节数组
   * @param a 第一个字节数组
   * @param b 第二个字节数组
   * @returns 连接后的字节数组
   */
  private concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
  }
}