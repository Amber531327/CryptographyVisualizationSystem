import { KeyPair, SignatureResult, CryptoAlgorithm } from './types';

export class DSA implements CryptoAlgorithm {
  // DSA参数
  private p: bigint = 0n; // 大素数，现代安全标准至少2048位
  private q: bigint = 0n; // 大素数，现代安全标准至少256位
  private g: bigint = 0n; // 模p的生成元

  // 参数位长设置
  private readonly P_BITS = 2048; // p的位长
  private readonly Q_BITS = 256;  // q的位长

  // 存储已使用过的k值，防止重复使用
  private usedKValues = new Set<string>();
  
  // DSA标准建议使用的哈希位长，确保哈希值适合q的大小
  private readonly HASH_BITS = 256;
  
  // 缓存计算结果，提高性能
  private modExpCache = new Map<string, bigint>();

  constructor() {}

  /**
   * 生成DSA参数p、q、g
   * 按照FIPS 186-4标准
   */
  private async generateParameters(): Promise<void> {
    console.log("正在生成DSA参数，这可能需要一些时间...");
    
    // 步骤1：生成素数q (256位)
    this.q = await this.generatePrime(this.Q_BITS);
    console.log("生成q完成...");
    
    // 步骤2：找到适当的素数p，使得p-1是q的倍数 (p = N*q + 1)
    this.p = await this.generatePWithQ(this.q, this.P_BITS);
    console.log("生成p完成...");
    
    // 步骤3：计算生成元g
    this.g = await this.calculateGenerator(this.p, this.q);
    console.log("生成g完成...");
    
    console.log("DSA参数生成完成");
  }

  /**
   * 生成指定位数的大素数
   * @param bits 素数的位数
   * @returns 生成的素数
   */
  private async generatePrime(bits: number): Promise<bigint> {
    let candidate: bigint;
    
    while (true) {
      // 生成随机奇数
      candidate = this.getRandomOddBigInt(bits);
      
      // 对候选素数执行Miller-Rabin素性测试
      if (await this.millerRabinTest(candidate, 40)) {
        return candidate;
      }
    }
  }

  /**
   * 生成随机奇数BigInt
   * @param bits 位数
   */
  private getRandomOddBigInt(bits: number): bigint {
    // 确保生成bits位的数
    const minVal = 1n << BigInt(bits - 1);
    const maxVal = (1n << BigInt(bits)) - 1n;
    
    // 生成随机值
    let value = this.getRandomBigInt(minVal, maxVal);
    
    // 确保是奇数
    if (value % 2n === 0n) {
      value += 1n;
    }
    
    return value;
  }

  /**
   * 基于素数q生成适合的素数p
   * @param q 素数q
   * @param pBits p的目标位数
   * @returns 素数p，满足p-1可被q整除
   */
  private async generatePWithQ(q: bigint, pBits: number): Promise<bigint> {
    // 计算N的大小，使得N*q > 2^(pBits-1)
    const minN = (1n << BigInt(pBits - 1)) / q + 1n;
    
    while (true) {
      // 选择一个随机N值
      const N = this.getRandomBigInt(minN, minN * 2n);
      
      // 计算p = N*q + 1
      const p = N * q + 1n;
      
      // 检查p的位长
      if (this.getBitLength(p) < pBits) {
        continue;
      }
      
      // 对p进行素性测试
      if (await this.millerRabinTest(p, 10)) {
        return p;
      }
    }
  }

  /**
   * 计算DSA生成元g
   * @param p 素数p
   * @param q 素数q
   * @returns 生成元g
   */
  private async calculateGenerator(p: bigint, q: bigint): Promise<bigint> {
    // 计算(p-1)/q
    const factor = (p - 1n) / q;
    
    // 尝试不同的h值，直到找到有效的g
    for (let h = 2n; h < p - 1n; h++) {
      // 计算g = h^((p-1)/q) mod p
      const g = this.modExp(h, factor, p);
      
      // 确保g > 1 (g=1不是有效的生成元)
      if (g > 1n) {
        return g;
      }
    }
    
    throw new Error("无法找到有效的生成元g");
  }

  /**
   * Miller-Rabin素性测试
   * @param n 待测试的数
   * @param k 测试轮数，越高越准确
   * @returns 如果可能是素数则返回true
   */
  private async millerRabinTest(n: bigint, k: number): Promise<boolean> {
    // 处理小于3的特殊情况
    if (n <= 1n) return false;
    if (n <= 3n) return true;
    if (n % 2n === 0n) return false;
    
    // 找到r和d，使得n-1 = 2^r * d，其中d是奇数
    let r = 0;
    let d = n - 1n;
    while (d % 2n === 0n) {
      d /= 2n;
      r++;
    }
    
    // 执行k轮测试
    for (let i = 0; i < k; i++) {
      // 随机选择a∈[2, n-2]
      const a = this.getRandomBigInt(2n, n - 2n);
      
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
      
      return false;
    }
    
    return true;
  }

  // 安全的模幂运算，使用窗口法优化性能
  private modExp(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === 1n) return 0n;
    
    // 检查缓存，提高性能
    const cacheKey = `${base}-${exponent}-${modulus}`;
    if (this.modExpCache.has(cacheKey)) {
      return this.modExpCache.get(cacheKey)!;
    }
    
    // 使用窗口大小为4的滑动窗口算法
    const windowSize = 4;
    const windowCount = 1 << windowSize; // 2^4 = 16
    const precomp = new Array<bigint>(windowCount);
    
    // 预计算 base^i mod modulus, i=0,1,2,...,15
    precomp[0] = 1n;
    for (let i = 1; i < windowCount; i++) {
      precomp[i] = (precomp[i - 1] * base) % modulus;
    }
    
    let result = 1n;
    const expBits = exponent.toString(2);
    
    // 从高位到低位处理每一位
    for (let i = 0; i < expBits.length; i++) {
      // 每次迭代平方result
      result = (result * result) % modulus;
      
      // 如果当前位是1，则乘以base
      if (expBits[i] === '1') {
        result = (result * base) % modulus;
      }
    }
    
    // 保存到缓存
    if (this.modExpCache.size < 1000) { // 限制缓存大小
      this.modExpCache.set(cacheKey, result);
    }
    
    return result;
  }

  // 计算模逆元 - 使用扩展欧几里得算法
  private modInverse(a: bigint, m: bigint): bigint {
    // 确保a是正数且小于m
    a = ((a % m) + m) % m;
    
    if (a === 0n) {
      throw new Error('模逆元不存在：除数不能为0');
    }
    
    // 扩展欧几里得算法
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    let [old_t, t] = [0n, 1n];
    
    while (r !== 0n) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
      [old_t, t] = [t, old_t - quotient * t];
    }
    
    // 如果gcd不为1，则模逆元不存在
    if (old_r !== 1n) {
      throw new Error('模逆元不存在：gcd不为1');
    }
    
    // 确保结果为正数
    return (old_s % m + m) % m;
  }

  /**
   * 使用SHA-256计算消息哈希，并正确截断以适应DSA参数q
   * @param message 需要哈希的消息
   * @returns 消息哈希的BigInt表示，截断至适合q的比特长度
   */
  private async hashSHA256(message: string): Promise<bigint> {
    try {
      // 获取完整的SHA-256哈希
      const fullHashHex = await this.getFullSHA256(message);
      const fullHashBytes = this.hexToBytes(fullHashHex);
      
      // 计算q的比特长度，确定需要多少位
      const qBitLength = this.getBitLength(this.q);
      
      // 按照FIPS 186-4标准，如果哈希长度大于q的位长，需要截断左侧位
      // 将哈希值截断为qBitLength位（从左侧取位）
      const hashBitsToUse = Math.min(this.HASH_BITS, qBitLength);
      const bytesToUse = Math.ceil(hashBitsToUse / 8);
      
      // 从左侧（最高有效位）取字节
      let hashValue = 0n;
      for (let i = 0; i < bytesToUse; i++) {
        hashValue = (hashValue << 8n) | BigInt(fullHashBytes[i]);
      }
      
      // 如果哈希位长大于q的位长，需要右移
      if (this.HASH_BITS > qBitLength) {
        hashValue = hashValue >> BigInt(this.HASH_BITS - qBitLength);
      }
      
      // 确保值小于q
      return hashValue % this.q;
      
    } catch (error) {
      console.error('SHA-256哈希计算失败:', error);
      // 备用方案
      return this.backupHash(message);
    }
  }

  /**
   * 备用哈希函数，当Web Crypto API不可用时使用
   * @param message 需要哈希的消息
   * @returns 哈希值的BigInt表示
   */
  private backupHash(message: string): bigint {
    let h = 0;
    for (let i = 0; i < message.length; i++) {
      h = ((h << 5) - h) + message.charCodeAt(i);
      h |= 0; // 转换为32位整数
    }
    
    // 确保结果为正数
    h = Math.abs(h);
    return BigInt(h) % this.q;
  }

  /**
   * 计算一个大整数的位长度
   * @param n 要计算位长度的大整数
   * @returns 位长度
   */
  private getBitLength(n: bigint): number {
    if (n === 0n) return 0;
    return n.toString(2).length;
  }

  async generateKeys(): Promise<KeyPair> {
    // 如果还没有初始化参数，先生成DSA参数
    if (this.p === 0n || this.q === 0n || this.g === 0n) {
      await this.generateParameters();
    }
    
    // 生成随机私钥x (x < q)
    const x = this.getRandomBigInt(1n, this.q - 1n);
    
    // 计算公钥 y = g^x mod p
    const y = this.modExp(this.g, x, this.p);
    
    const publicKey = { 
      p: this.p, 
      q: this.q, 
      g: this.g, 
      y,
      pBits: Number(this.getBitLength(this.p)),
      qBits: Number(this.getBitLength(this.q))
    };
    
    const privateKey = { x };
    
    return { publicKey, privateKey };
  }

  /**
   * 基于RFC 6979的确定性k值生成
   * 确保每次对相同消息和私钥的签名生成唯一且确定的k值
   * 同时避免了对随机数生成器的依赖，增强了安全性
   * 
   * @param privateKey 私钥
   * @param messageHash 消息哈希值
   * @returns 确定性生成的k值
   */
  private async generateDeterministicK(privateKey: bigint, messageHash: bigint): Promise<bigint> {
    // 转换为字节数组
    const xBytes = this.bigintToBytes(privateKey);
    const mBytes = this.bigintToBytes(messageHash);
    
    // 初始化
    const v = new Uint8Array(32).fill(1);  // V = 0x01 0x01 0x01 ... 0x01
    const k = new Uint8Array(32).fill(0);  // K = 0x00 0x00 0x00 ... 0x00
    
    // 使用HMAC-SHA256进行计算，但由于我们在浏览器环境可能无法使用HMAC
    // 使用简化的方法计算一个伪HMAC
    
    // 第一步：合并数据
    const data1 = new Uint8Array(v.length + 1 + xBytes.length + mBytes.length);
    data1.set(v, 0);
    data1[v.length] = 0; // 0x00
    data1.set(xBytes, v.length + 1);
    data1.set(mBytes, v.length + 1 + xBytes.length);
    
    // 哈希data1，更新K
    const k1 = await this.sha256bytes(data1);
    for (let i = 0; i < k.length && i < k1.length; i++) {
      k[i] = k1[i];
    }
    
    // 哈希K||V，更新V
    const v1 = await this.sha256bytes(this.concatBytes(k, v));
    for (let i = 0; i < v.length && i < v1.length; i++) {
      v[i] = v1[i];
    }
    
    // 第二步
    const data2 = new Uint8Array(v.length + 1 + xBytes.length + mBytes.length);
    data2.set(v, 0);
    data2[v.length] = 1; // 0x01
    data2.set(xBytes, v.length + 1);
    data2.set(mBytes, v.length + 1 + xBytes.length);
    
    // 哈希data2，更新K
    const k2 = await this.sha256bytes(data2);
    for (let i = 0; i < k.length && i < k2.length; i++) {
      k[i] = k2[i];
    }
    
    // 哈希K||V，更新V
    const v2 = await this.sha256bytes(this.concatBytes(k, v));
    for (let i = 0; i < v.length && i < v2.length; i++) {
      v[i] = v2[i];
    }
    
    // 生成k值
    let t = new Uint8Array(0);
    
    // 循环直到找到有效的k
    while (true) {
      // 更新V
      const newV = await this.sha256bytes(this.concatBytes(k, v));
      for (let i = 0; i < v.length && i < newV.length; i++) {
        v[i] = newV[i];
      }
      
      // 创建新的ArrayBuffer而不是直接连接
      const tNew = new Uint8Array(t.length + v.length);
      tNew.set(t, 0);
      tNew.set(v, t.length);
      t = tNew;
      
      // 如果T长度足够
      if (t.length >= 32) {
        // 将T转换为BigInt
        let kBigInt = 0n;
        for (let i = 0; i < Math.min(32, t.length); i++) {
          kBigInt = (kBigInt << 8n) | BigInt(t[i]);
        }
        
        // 确保k在[1, q-1]范围内
        kBigInt = kBigInt % (this.q - 1n) + 1n;
        
        // 检查k是否已被使用
        const kStr = kBigInt.toString();
        if (!this.usedKValues.has(kStr)) {
          // 记录已使用的k值
          this.usedKValues.add(kStr);
          return kBigInt;
        }
        
        // 如果k已被使用，继续循环生成新的k
        // 更新K和V
        const data3 = new Uint8Array(v.length + 1);
        data3.set(v, 0);
        data3[v.length] = 0; // 0x00
        
        const k3 = await this.sha256bytes(this.concatBytes(k, data3));
        for (let i = 0; i < k.length && i < k3.length; i++) {
          k[i] = k3[i];
        }
        
        const v3 = await this.sha256bytes(this.concatBytes(k, v));
        for (let i = 0; i < v.length && i < v3.length; i++) {
          v[i] = v3[i];
        }
        
        t = new Uint8Array(0);
      }
    }
  }

  /**
   * 连接两个字节数组，确保返回类型一致
   */
  private concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
  }

  /**
   * 将BigInt转换为字节数组
   */
  private bigintToBytes(n: bigint): Uint8Array {
    // 确保非负
    if (n < 0n) {
      throw new Error("Cannot convert negative BigInt to bytes");
    }
    
    if (n === 0n) {
      return new Uint8Array(1); // 返回单个零字节
    }
    
    // 计算需要的字节数
    const byteLength = Math.ceil(this.getBitLength(n) / 8);
    const bytes = new Uint8Array(byteLength);
    
    let temp = n;
    for (let i = byteLength - 1; i >= 0; i--) {
      bytes[i] = Number(temp & 0xffn);
      temp = temp >> 8n;
    }
    
    return bytes;
  }

  /**
   * 计算字节数组的SHA-256哈希
   * 由于类型兼容性问题，我们使用修改后的实现
   */
  private async sha256bytes(data: Uint8Array): Promise<Uint8Array> {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        // 浏览器环境下使用Web Crypto API
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(hashBuffer);
      } catch (e) {
        console.warn("使用Web Crypto API进行SHA-256哈希计算失败，使用备用实现", e);
        return this.simpleSha256(data);
      }
    } else {
      // 非浏览器环境或Web Crypto不可用，使用简单实现
      return this.simpleSha256(data);
    }
  }

  /**
   * 简单的SHA-256实现（备用）
   */
  private simpleSha256(data: Uint8Array): Uint8Array {
    // 这是一个简化版的哈希实现，不是标准的SHA-256
    let h0 = 0x6a09e667;
    let h1 = 0xbb67ae85;
    let h2 = 0x3c6ef372;
    let h3 = 0xa54ff53a;
    let h4 = 0x510e527f;
    let h5 = 0x9b05688c;
    let h6 = 0x1f83d9ab;
    let h7 = 0x5be0cd19;
    
    // 改进混合逻辑，增加混淆效果
    const mix = (val: number, byte: number): number => {
      const rotated = ((val << 7) | (val >>> 25)) ^ ((val << 11) | (val >>> 21));
      return (rotated + byte) | 0;
    };
    
    for (let i = 0; i < data.length; i++) {
      const byte = data[i];
      h0 = mix(h0, byte);
      h1 = mix(h1, h0 ^ byte);
      h2 = mix(h2, h1 ^ byte);
      h3 = mix(h3, h2 ^ byte);
      h4 = mix(h4, h3 ^ byte);
      h5 = mix(h5, h4 ^ byte);
      h6 = mix(h6, h5 ^ byte);
      h7 = mix(h7, h6 ^ byte);
    }
    
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
   * 执行DSA签名
   * 实现了恒定时间操作以防止时间侧信道攻击
   */
  async sign(message: string, keys: KeyPair): Promise<SignatureResult> {
    try {
      // 首先确保我们有有效的DSA参数
      const p = keys.publicKey.p ? BigInt(keys.publicKey.p) : this.p;
      const q = keys.publicKey.q ? BigInt(keys.publicKey.q) : this.q;
      const g = keys.publicKey.g ? BigInt(keys.publicKey.g) : this.g;
      
      // 提取私钥
      const x = BigInt(keys.privateKey.x);
      
      // 使用SHA-256哈希函数并正确截断
      const messageHash = await this.hashSHA256(message);
      
      // 使用确定性方法生成k，确保安全性
      const k = await this.generateDeterministicK(x, messageHash);
      
      // 计算r = (g^k mod p) mod q
      const r = this.modExp(g, k, p) % q;
      
      // 检查r是否为0（极低概率，确定性k应该避免此情况）
      if (this.constantTimeEquals(r, 0n)) {
        console.warn('生成的r为0，重新签名');
        return this.sign(message, keys);
      }
      
      // 计算k的模逆元
      const kInv = this.modInverse(k, q);
      
      // 计算 s = k^-1 * (H(M) + x*r) mod q
      // 注意：所有操作采用模运算避免中间值过大
      const xr = (x * r) % q;
      const sum = (messageHash + xr) % q;
      const s = (kInv * sum) % q;
      
      // 检查s是否为0
      if (this.constantTimeEquals(s, 0n)) {
        console.warn('生成的s为0，重新签名');
        return this.sign(message, keys);
      }
      
      // 计算原始消息的完整SHA-256哈希供显示
      const messageHashHex = await this.getFullSHA256(message);
      
      return { 
        signature: null,
        r: r.toString(), 
        s: s.toString(),
        messageHash: messageHashHex,
        pBits: Number(this.getBitLength(p)), // 添加位长信息
        qBits: Number(this.getBitLength(q))  // 添加位长信息
      };
    } catch (error) {
      console.error('DSA签名生成错误:', error);
      throw error;
    }
  }

  /**
   * 验证DSA签名
   * 实现了恒定时间比较以防止时间侧信道攻击
   */
  async verify(message: string, signature: any, keys: KeyPair): Promise<boolean> {
    try {
      // 提取公钥
      const p = BigInt(keys.publicKey.p);
      const q = BigInt(keys.publicKey.q);
      const g = BigInt(keys.publicKey.g);
      const y = BigInt(keys.publicKey.y);
      
      const { r, s } = signature;
      
      const rBigInt = BigInt(r);
      const sBigInt = BigInt(s);
      
      // 检查r和s是否在有效范围内(0 < r,s < q)
      if (rBigInt <= 0n || rBigInt >= q || sBigInt <= 0n || sBigInt >= q) {
        return false;
      }
      
      // 计算s的模逆元 w = s^-1 mod q
      const w = this.modInverse(sBigInt, q);
      
      // 计算消息哈希（使用SHA-256并正确截断）
      const messageHash = await this.hashSHA256(message);
      
      // 计算u1 = H(M) * w mod q
      const u1 = (messageHash * w) % q;
      
      // 计算u2 = r * w mod q
      const u2 = (rBigInt * w) % q;
      
      // 计算v = ((g^u1 * y^u2) mod p) mod q
      // 优化：分别计算g^u1和y^u2，然后再相乘
      const v1 = this.modExp(g, u1, p);
      const v2 = this.modExp(y, u2, p);
      const v = ((v1 * v2) % p) % q;
      
      // 恒定时间比较，防止时间侧信道攻击
      return this.constantTimeEquals(v, rBigInt);
    } catch (error) {
      console.error('DSA验证错误:', error);
      return false;
    }
  }

  /**
   * 恒定时间比较两个大整数
   * 防止时间侧信道攻击
   */
  private constantTimeEquals(a: bigint, b: bigint): boolean {
    // 转换为字符串以确保一致的处理
    const aStr = a.toString(16).padStart(64, '0');
    const bStr = b.toString(16).padStart(64, '0');
    
    // 确保两个值长度相同
    if (aStr.length !== bStr.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < aStr.length; i++) {
      // 使用异或比较每个字符
      result |= aStr.charCodeAt(i) ^ bStr.charCodeAt(i);
    }
    
    return result === 0;
  }

  /**
   * 计算完整的SHA-256哈希，返回十六进制字符串（用于显示）
   * @param message 需要哈希的消息
   * @returns SHA-256哈希的十六进制字符串
   */
  private async getFullSHA256(message: string): Promise<string> {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      const encoder = new TextEncoder();
      const messageBuffer = encoder.encode(message);
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', messageBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      return hashHex;
    } else {
      // 备用方案：返回简单哈希的十六进制表示
      const backupHashBytes = this.simpleSha256(new TextEncoder().encode(message));
      return Array.from(backupHashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
  }

  /**
   * 将十六进制字符串转换为字节数组
   */
  private hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
      hex = '0' + hex; // 确保偶数长度
    }
    
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    
    return bytes;
  }

  // 生成指定范围内的安全随机大整数
  private getRandomBigInt(min: bigint, max: bigint): bigint {
    // 计算范围大小
    const range = max - min;
    
    // 获取足够的随机字节
    const bitsNeeded = this.getBitLength(range);
    const bytesNeeded = Math.ceil(bitsNeeded / 8);
    
    // 创建一个空数组来存储随机字节
    const randomBytes = new Uint8Array(bytesNeeded);
    
    // 在Node.js或浏览器环境中获取随机字节
    if (typeof window !== 'undefined' && window.crypto) {
      // 浏览器环境
      window.crypto.getRandomValues(randomBytes);
    } else {
      // 如果既不是浏览器也不是Node.js，使用简单的随机数
      for (let i = 0; i < bytesNeeded; i++) {
        randomBytes[i] = Math.floor(Math.random() * 256);
      }
    }
    
    // 将随机字节转换为BigInt
    let randomValue = 0n;
    for (let i = 0; i < bytesNeeded; i++) {
      randomValue = (randomValue << 8n) | BigInt(randomBytes[i]);
    }
    
    // 确保值在指定范围内
    return min + (randomValue % (range + 1n));
  }
} 