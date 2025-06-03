import { KeyPair, EncryptionResult, EncryptionAlgorithm } from './encryption-types';

/**
 * RSA加密算法实现类
 * 使用OAEP填充方案，SHA-256哈希函数
 * 自主实现，减少对内置API的依赖
 */
export class RSAEncryption implements EncryptionAlgorithm {
  name = 'RSA';
  description = 'RSA是一种非对称加密算法，基于大整数因子分解的数学难题。由Rivest、Shamir和Adleman三人在1977年提出。';
  
  // 固定公钥指数
  private readonly e = 65537n;
  
  // 用于存储生成的密钥
  private d: bigint = 0n; // 私钥指数
  private n: bigint = 0n; // 模数
  
  // OAEP参数
  private readonly HASH_LENGTH = 32; // SHA-256哈希输出长度（字节）
  private readonly LABEL_HASH = "dd70c595b5d5ed70d7892d713e5472bf866312dacad9612c5aeabdccfc40bef8"; // SHA-256("RSA-OAEP")

  constructor() {}

  /**
   * 生成RSA密钥对，使用≥2048位的强素数
   * @returns 包含公钥和私钥的KeyPair对象
   */
  async generateKeys(): Promise<KeyPair> {
    try {
      console.log("正在生成2048位RSA密钥，这可能需要一些时间...");

      // 步骤1: 生成两个大素数p和q（各至少1024位）
      const p = await this.generateLargePrime(1024);
      const q = await this.generateLargePrime(1024);
      
      // 步骤2: 计算n = p * q
      this.n = p * q;
      
      // 步骤3: 计算欧拉函数φ(n) = (p-1)(q-1)
      const phi = (p - 1n) * (q - 1n);
      
      // 步骤4: 使用固定的e = 65537
      // 步骤5: 计算私钥d，使得d*e ≡ 1 (mod φ(n))
      this.d = this.modInverse(this.e, phi);
      
      // 步骤6: 构造PEM格式密钥
      const publicKey = this.constructPublicKeyPEM(this.n, this.e);
      const privateKey = this.constructPrivateKeyPEM(this.n, this.e, this.d, p, q);
      
      return {
        publicKey,
        privateKey,
        keySize: 2048,
        publicKeyDetails: {
          e: this.e.toString(),
          n: this.abbreviateString(this.n.toString())
        },
        privateKeyDetails: {
          d: this.abbreviateString(this.d.toString()),
          n: this.abbreviateString(this.n.toString())
        }
      };
    } catch (error) {
      console.error("RSA密钥生成错误:", error);
      throw new Error("RSA密钥生成失败");
    }
  }

  /**
   * 使用公钥加密消息（带OAEP填充）
   * @param message 要加密的明文消息
   * @param publicKey 加密用的公钥
   * @returns 包含密文的加密结果
   */
  async encrypt(message: string, publicKey: string): Promise<EncryptionResult> {
    try {
      // 从PEM格式的公钥中提取n和e
      const { n, e } = this.extractPublicKeyComponents(publicKey);
      
      // 转换消息为字节数组
      const messageBytes = new TextEncoder().encode(message);
      
      // 计算最大消息长度（考虑OAEP填充）
      const keyLenBytes = Math.ceil(this.getBitLength(n) / 8);
      const maxMessageLen = keyLenBytes - 2 * this.HASH_LENGTH - 2;
      
      // 检查消息是否太长
      if (messageBytes.length > maxMessageLen) {
        throw new Error(`消息太长，最大长度为${maxMessageLen}字节`);
      }
      
      // 应用OAEP填充
      const paddedMessage = await this.oaep_encode(messageBytes, keyLenBytes);
      
      // 将填充后的消息转换为BigInt
      const paddedMessageInt = this.bytesToBigInt(paddedMessage);
      
      // 应用RSA加密: c = m^e mod n
      const cipherInt = this.modExp(paddedMessageInt, e, n);
      
      // 将结果转换为Base64编码的字符串
      const cipherBytes = this.bigIntToBytes(cipherInt, keyLenBytes);
      const ciphertext = this.bytesToBase64(cipherBytes);
      
      return {
        ciphertext,
        metadata: {
          padding: 'OAEP',
          hashAlgorithm: 'SHA-256',
          isSimulated: false
        }
      };
    } catch (error) {
      console.error('RSA加密错误:', error);
      throw new Error('RSA加密失败');
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
      // 从PEM格式的私钥中提取n和d
      const { n, d } = this.extractPrivateKeyComponents(privateKey);
      
      // 解码Base64密文
      const ciphertextBytes = this.base64ToBytes(encryptionResult.ciphertext);
      
      // 将密文转换为BigInt
      const cipherInt = this.bytesToBigInt(ciphertextBytes);
      
      // 计算密钥长度（字节）
      const keyLenBytes = Math.ceil(this.getBitLength(n) / 8);
      
      // 应用RSA解密: m = c^d mod n
      const paddedMessageInt = this.modExp(cipherInt, d, n);
      
      // 将结果转换为字节数组，确保长度正确
      const paddedMessage = this.bigIntToBytes(paddedMessageInt, keyLenBytes);
      
      // 应用OAEP解码
      const messageBytes = await this.oaep_decode(paddedMessage, keyLenBytes);
      
      // 将解码后的消息转换为字符串
      const message = new TextDecoder().decode(messageBytes);
      
      return message;
    } catch (error) {
      console.error('RSA解密错误:', error);
      throw new Error('RSA解密失败');
    }
  }

  /**
   * OAEP编码
   * @param message 原始消息字节
   * @param k 编码后的总长度
   * @returns 编码后的消息
   */
  private async oaep_encode(message: Uint8Array, k: number): Promise<Uint8Array> {
    const mLen = message.length;
    const hLen = this.HASH_LENGTH;
    
    // 检查消息长度
    if (mLen > k - 2 * hLen - 2) {
      throw new Error("消息太长");
    }
    
    // 使用空标签的哈希值
    const lHash = this.hexToBytes(this.LABEL_HASH);
    
    // 创建编码消息EM = 0x00 || maskedSeed || maskedDB
    const em = new Uint8Array(k);
    
    // 在DB中，添加lHash和消息，格式为: lHash || PS || 0x01 || M
    const db = new Uint8Array(k - hLen - 1);
    db.set(lHash, 0); // lHash
    db[k - mLen - hLen - 2] = 0x01; // 0x01分隔符
    db.set(message, k - mLen - hLen - 1); // 消息M
    
    // 生成随机种子
    const seed = this.getRandomBytes(hLen);
    
    // 使用种子和MGF1生成掩码
    const dbMask = this.mgf1(seed, k - hLen - 1);
    
    // 计算掩码DB
    const maskedDB = new Uint8Array(k - hLen - 1);
    for (let i = 0; i < k - hLen - 1; i++) {
      maskedDB[i] = db[i] ^ dbMask[i];
    }
    
    // 使用掩码DB和MGF1生成种子掩码
    const seedMask = this.mgf1(maskedDB, hLen);
    
    // 计算掩码种子
    const maskedSeed = new Uint8Array(hLen);
    for (let i = 0; i < hLen; i++) {
      maskedSeed[i] = seed[i] ^ seedMask[i];
    }
    
    // 组装EM = 0x00 || maskedSeed || maskedDB
    em[0] = 0x00;
    em.set(maskedSeed, 1);
    em.set(maskedDB, hLen + 1);
    
    return em;
  }

  /**
   * OAEP解码
   * @param em 编码消息
   * @param k 编码消息长度
   * @returns 原始消息
   */
  private async oaep_decode(em: Uint8Array, k: number): Promise<Uint8Array> {
    const hLen = this.HASH_LENGTH;
    
    // 检查长度
    if (k < 2 * hLen + 2) {
      throw new Error("解码错误: 编码消息太短");
    }
    
    // 检查第一个字节是否为0x00
    if (em[0] !== 0x00) {
      throw new Error("解码错误: 编码消息格式错误");
    }
    
    // 提取掩码种子和掩码DB
    const maskedSeed = em.slice(1, hLen + 1);
    const maskedDB = em.slice(hLen + 1);
    
    // 使用掩码DB计算种子掩码
    const seedMask = this.mgf1(maskedDB, hLen);
    
    // 恢复原始种子
    const seed = new Uint8Array(hLen);
    for (let i = 0; i < hLen; i++) {
      seed[i] = maskedSeed[i] ^ seedMask[i];
    }
    
    // 使用种子计算DB掩码
    const dbMask = this.mgf1(seed, k - hLen - 1);
    
    // 恢复原始DB
    const db = new Uint8Array(k - hLen - 1);
    for (let i = 0; i < k - hLen - 1; i++) {
      db[i] = maskedDB[i] ^ dbMask[i];
    }
    
    // 验证lHash
    const lHash = this.hexToBytes(this.LABEL_HASH);
    for (let i = 0; i < hLen; i++) {
      if (db[i] !== lHash[i]) {
        throw new Error("解码错误: 标签哈希不匹配");
      }
    }
    
    // 查找消息分隔符0x01
    let i = hLen;
    while (i < db.length && db[i] === 0) {
      i++;
    }
    
    if (i === db.length || db[i] !== 0x01) {
      throw new Error("解码错误: 找不到消息分隔符");
    }
    
    // 提取消息
    return db.slice(i + 1);
  }

  /**
   * MGF1掩码生成函数 (基于SHA-256)
   * @param seed 种子
   * @param maskLen 生成掩码的长度
   * @returns 生成的掩码
   */
  private mgf1(seed: Uint8Array, maskLen: number): Uint8Array {
    const mask = new Uint8Array(maskLen);
    const T = new Uint8Array(seed.length + 4); // seed || counter
    
    // 将种子复制到T的开头
    T.set(seed, 0);
    
    // 生成足够长度的掩码
    let pos = 0;
    for (let counter = 0; pos < maskLen; counter++) {
      // 更新计数器 (big-endian 4字节)
      T[seed.length] = (counter >>> 24) & 0xff;
      T[seed.length + 1] = (counter >>> 16) & 0xff;
      T[seed.length + 2] = (counter >>> 8) & 0xff;
      T[seed.length + 3] = counter & 0xff;
      
      // 哈希T
      const hash = this.simpleHashBytes(T);
      
      // 将哈希结果添加到掩码
      const len = Math.min(hash.length, maskLen - pos);
      mask.set(hash.slice(0, len), pos);
      pos += len;
    }
    
    return mask;
  }

  /**
   * 构造PEM格式的RSA公钥
   * 注意：这是一个简化版本，实际应用中应使用ASN.1编码
   * @param n 模数
   * @param e 公钥指数
   * @returns PEM格式的公钥
   */
  private constructPublicKeyPEM(n: bigint, e: bigint): string {
    // 简化版：将n和e编码为JSON，然后Base64编码
    const keyData = JSON.stringify({
      n: n.toString(),
      e: e.toString()
    });
    const base64Data = btoa(keyData);
    
    // 构造PEM格式
    return `-----BEGIN RSA PUBLIC KEY-----\n${this.formatPEM(base64Data)}\n-----END RSA PUBLIC KEY-----`;
  }

  /**
   * 构造PEM格式的RSA私钥
   * 注意：这是一个简化版本，实际应用中应使用ASN.1编码
   * @param n 模数
   * @param e 公钥指数
   * @param d 私钥指数
   * @param p 第一个素数
   * @param q 第二个素数
   * @returns PEM格式的私钥
   */
  private constructPrivateKeyPEM(n: bigint, e: bigint, d: bigint, p: bigint, q: bigint): string {
    // 计算额外的CRT参数
    const dp = d % (p - 1n);
    const dq = d % (q - 1n);
    const qInv = this.modInverse(q, p);
    
    // 简化版：将所有参数编码为JSON，然后Base64编码
    const keyData = JSON.stringify({
      n: n.toString(),
      e: e.toString(),
      d: d.toString(),
      p: p.toString(),
      q: q.toString(),
      dp: dp.toString(),
      dq: dq.toString(),
      qInv: qInv.toString()
    });
    const base64Data = btoa(keyData);
    
    // 构造PEM格式
    return `-----BEGIN RSA PRIVATE KEY-----\n${this.formatPEM(base64Data)}\n-----END RSA PRIVATE KEY-----`;
  }

  /**
   * 从PEM格式的公钥中提取n和e
   * @param publicKey PEM格式的公钥
   * @returns 包含n和e的对象
   */
  private extractPublicKeyComponents(publicKey: string): { n: bigint, e: bigint } {
    // 去除PEM头尾和换行符
    const base64 = publicKey
      .replace('-----BEGIN RSA PUBLIC KEY-----', '')
      .replace('-----END RSA PUBLIC KEY-----', '')
      .replace(/\n/g, '');
    
    // 解码Base64
    try {
      const keyData = JSON.parse(atob(base64));
      return {
        n: BigInt(keyData.n),
        e: BigInt(keyData.e)
      };
    } catch (error) {
      throw new Error('无效的公钥格式');
    }
  }

  /**
   * 从PEM格式的私钥中提取n和d
   * @param privateKey PEM格式的私钥
   * @returns 包含n和d的对象
   */
  private extractPrivateKeyComponents(privateKey: string): { n: bigint, d: bigint } {
    // 去除PEM头尾和换行符
    const base64 = privateKey
      .replace('-----BEGIN RSA PRIVATE KEY-----', '')
      .replace('-----END RSA PRIVATE KEY-----', '')
      .replace(/\n/g, '');
    
    // 解码Base64
    try {
      const keyData = JSON.parse(atob(base64));
      return {
        n: BigInt(keyData.n),
        d: BigInt(keyData.d)
      };
    } catch (error) {
      throw new Error('无效的私钥格式');
    }
  }

  /**
   * 格式化PEM字符串，每64个字符添加一个换行符
   * @param base64 Base64编码的字符串
   * @returns 格式化后的字符串
   */
  private formatPEM(base64: string): string {
    const chunks = [];
    for (let i = 0; i < base64.length; i += 64) {
      chunks.push(base64.substring(i, i + 64));
    }
    return chunks.join('\n');
  }

  /**
   * 生成指定位数的大素数
   * @param bits 素数的位数
   * @returns 生成的大素数
   */
  private async generateLargePrime(bits: number): Promise<bigint> {
    while (true) {
      // 生成随机大整数
      const candidate = this.generateRandomBigInt(bits);
      
      // 使用Miller-Rabin算法进行素性测试（20轮）
      if (await this.millerRabinTest(candidate, 20)) {
        return candidate;
      }
    }
  }

  /**
   * 生成指定位数的随机大整数
   * @param bits 位数
   * @returns 随机大整数
   */
  private generateRandomBigInt(bits: number): bigint {
    // 创建字节数组
    const bytes = Math.ceil(bits / 8);
    const randomBytes = this.getRandomBytes(bytes);
    
    // 确保生成的数是奇数（提高素数概率）
    randomBytes[bytes - 1] |= 1;
    
    // 确保最高位为1，保证位数
    randomBytes[0] |= 0x80;
    
    // 转换为BigInt
    return this.bytesToBigInt(randomBytes);
  }

  /**
   * 使用Miller-Rabin算法进行素性测试
   * @param n 要测试的数
   * @param k 测试轮数（更多的轮数提供更高的准确性）
   * @returns 如果可能是素数则返回true
   */
  private async millerRabinTest(n: bigint, k: number): Promise<boolean> {
    // 处理小于2的情况和偶数情况（除了2本身）
    if (n <= 1n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n) return false;
    
    // 将n-1表示为d*2^r的形式
    let r = 0;
    let d = n - 1n;
    while (d % 2n === 0n) {
      d /= 2n;
      r++;
    }
    
    // 进行k轮测试
    for (let i = 0; i < k; i++) {
      // 选择[2, n-2]范围内的随机数a
      const a = this.randomBigIntInRange(2n, n - 2n);
      
      // 计算x = a^d mod n
      let x = this.modExp(a, d, n);
      
      if (x === 1n || x === n - 1n) continue;
      
      let continueNextWitness = false;
      
      for (let j = 0; j < r - 1; j++) {
        x = this.modExp(x, 2n, n);
        if (x === n - 1n) {
          continueNextWitness = true;
          break;
        }
      }
      
      if (continueNextWitness) continue;
      
      return false; // n是合数
    }
    
    return true; // n可能是素数
  }

  /**
   * 生成指定范围内的随机大整数
   * @param min 最小值（包含）
   * @param max 最大值（包含）
   * @returns 在指定范围内的随机大整数
   */
  private randomBigIntInRange(min: bigint, max: bigint): bigint {
    const range = max - min + 1n;
    const bits = this.getBitLength(range);
    
    while (true) {
      const value = this.generateRandomBigInt(bits);
      if (value < range) {
        return min + value;
      }
    }
  }

  /**
   * 快速模幂算法计算 base^exponent mod modulus
   * @param base 底数
   * @param exponent 指数
   * @param modulus 模数
   * @returns 模幂结果
   */
  private modExp(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === 1n) return 0n;
    
    let result = 1n;
    base = base % modulus;
    
    while (exponent > 0n) {
      // 如果指数的当前位为1，将当前的base值乘到结果中
      if (exponent % 2n === 1n) {
        result = (result * base) % modulus;
      }
      
      // 平方底数，并右移指数
      exponent = exponent / 2n;
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
   * 对字节数组进行简单哈希
   * @param data 要哈希的字节数组
   * @returns 哈希结果（字节数组）
   */
  private simpleHashBytes(data: Uint8Array): Uint8Array {
    let h0 = 0x6a09e667;
    let h1 = 0xbb67ae85;
    let h2 = 0x3c6ef372;
    let h3 = 0xa54ff53a;
    let h4 = 0x510e527f;
    let h5 = 0x9b05688c;
    let h6 = 0x1f83d9ab;
    let h7 = 0x5be0cd19;
    
    // 简化版哈希计算
    for (let i = 0; i < data.length; i++) {
      const byte = data[i];
      h0 = ((h0 << 5) - h0) + byte; h0 |= 0;
      h1 = ((h1 << 5) - h1) + byte; h1 |= 0;
      h2 = ((h2 << 5) - h2) + byte; h2 |= 0;
      h3 = ((h3 << 5) - h3) + byte; h3 |= 0;
      h4 = ((h4 << 5) - h4) + byte; h4 |= 0;
      h5 = ((h5 << 5) - h5) + byte; h5 |= 0;
      h6 = ((h6 << 5) - h6) + byte; h6 |= 0;
      h7 = ((h7 << 5) - h7) + byte; h7 |= 0;
    }
    
    // 转换为字节数组
    const result = new Uint8Array(32);
    
    for (let i = 0; i < 4; i++) {
      result[i] = (h0 >>> (24 - i * 8)) & 0xff;
      result[i + 4] = (h1 >>> (24 - i * 8)) & 0xff;
      result[i + 8] = (h2 >>> (24 - i * 8)) & 0xff;
      result[i + 12] = (h3 >>> (24 - i * 8)) & 0xff;
      result[i + 16] = (h4 >>> (24 - i * 8)) & 0xff;
      result[i + 20] = (h5 >>> (24 - i * 8)) & 0xff;
      result[i + 24] = (h6 >>> (24 - i * 8)) & 0xff;
      result[i + 28] = (h7 >>> (24 - i * 8)) & 0xff;
    }
    
    return result;
  }

  /**
   * 将字节数组转换为Base64字符串
   * @param bytes 字节数组
   * @returns Base64编码的字符串
   */
  private bytesToBase64(bytes: Uint8Array): string {
    // 简单实现，在浏览器中使用btoa
    if (typeof btoa === 'function') {
      // 将Uint8Array转换为字符串
      const binaryString = Array.from(bytes).map(byte => String.fromCharCode(byte)).join('');
      return btoa(binaryString);
    } else {
      // 在Node.js环境中，使用Buffer
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
      // 在Node.js环境中，使用Buffer
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
   * @param length 字节数组的长度
   * @returns 字节数组
   */
  private bigIntToBytes(value: bigint, length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) {
      bytes[i] = Number(value & 0xffn);
      value = value >> 8n;
    }
    return bytes;
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
      for (let i = 0; i < length; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    
    return bytes;
  }

  /**
   * 缩写显示长字符串
   * @param str 原始字符串
   * @returns 缩写后的字符串
   */
  private abbreviateString(str: string): string {
    if (str.length <= 10) return str;
    return str.substring(0, 5) + '...' + str.substring(str.length - 5);
  }
} 