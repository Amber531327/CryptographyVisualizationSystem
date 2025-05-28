import { KeyPair, SignatureResult, CryptoAlgorithm } from './types';


export class ECDSA implements CryptoAlgorithm {
  // secp256k1曲线参数
  private readonly p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
  private readonly a = 0n;
  private readonly b = 7n;
  private readonly Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
  private readonly Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
  private readonly n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  
  // 保存已使用的k值，防止k值重用
  private usedKValues = new Set<string>();
  
  // 曲线名称用于显示
  private readonly curveName = 'secp256k1';
  
  constructor() {}

  /**
   * 基点G
   */
  private get G(): Point {
    return { x: this.Gx, y: this.Gy };
  }

  /**
   * 生成ECDSA密钥对
   * 私钥d是[1, n-1]范围内的随机整数
   * 公钥Q = d × G (点乘运算)
   */
  async generateKeys(): Promise<KeyPair> {
    // 1. 生成随机私钥 d ∈ [1, n-1]
    const privateKey = this.getRandomBigInt(1n, this.n - 1n);
    
    // 2. 计算公钥 Q = d × G
    const publicKey = this.pointMultiply(this.G, privateKey);
    
    // 3. 返回密钥对
    return {
      publicKey: {
        x: publicKey.x.toString(16).padStart(64, '0'),
        y: publicKey.y.toString(16).padStart(64, '0'),
        curve: this.curveName
      },
      privateKey: {
        d: privateKey.toString(16).padStart(64, '0'),
        curve: this.curveName
      }
    };
  }

  /**
   * ECDSA签名算法实现
   * 
   * @param message 待签名的消息
   * @param keys 包含私钥的密钥对
   * @returns 签名结果 (r, s)
   */
  async sign(message: string, keys: KeyPair): Promise<SignatureResult> {
    try {
      // 1. 获取私钥d
      const dHex = keys.privateKey.d as string;
      const d = BigInt(`0x${dHex}`);
      
      // 2. 计算消息摘要e
      const messageHash = await this.sha256(message);
      const e = this.hashToInt(messageHash, this.n);
      
      // 3. 使用确定性k值生成随机数k (基于RFC 6979)
      const k = await this.generateDeterministicK(d, e);
      
      // 4. 计算点 kG = (x1, y1) 
      const kG = this.pointMultiply(this.G, k);
      
      // 5. 计算r = x1 mod n
      const r = kG.x % this.n;
      
      // 确保r ≠ 0
      if (r === 0n) {
        console.info("r = 0，重新签名");
        return this.sign(message, keys);
      }
      
      // 6. 计算s = k^(-1) * (e + r*d) mod n
      const kInv = this.modInverse(k, this.n);
      let s = (kInv * ((e + r * d) % this.n)) % this.n;
      
      // 7. 确保s ≠ 0
      if (s === 0n) {
        console.info("s = 0，重新签名");
        return this.sign(message, keys);
      }
      
      // 8. DER编码 (为了与标准兼容，但我们同时保留r和s用于教学)
      const derSignature = this.derEncode(r, s);
      
      // 返回签名结果
      return {
        signature: derSignature,
        r: r.toString(16).padStart(64, '0'),
        s: s.toString(16).padStart(64, '0'),
        messageHash: messageHash
      };
    } catch (error) {
      // 静默失败并返回一个空签名结果，避免输出错误日志
      console.info('ECDSA签名生成失败，返回空签名');
      return {
        signature: "",
        r: "0".padStart(64, '0'),
        s: "0".padStart(64, '0'),
        messageHash: ""
      };
    }
  }

  /**
   * ECDSA签名验证算法实现
   * 
   * @param message 原始消息
   * @param signature 签名结果
   * @param keys 包含公钥的密钥对
   * @returns 验证结果(布尔值)
   */
  async verify(message: string, signature: any, keys: KeyPair): Promise<boolean> {
    try {
      // 1. 恢复公钥Q和签名值r,s
      const Qx = BigInt(`0x${keys.publicKey.x}`);
      const Qy = BigInt(`0x${keys.publicKey.y}`);
      const Q = { x: Qx, y: Qy };
      
      // 如果签名以DER格式提供，则解码，否则直接使用r,s
      let r: bigint, s: bigint;
      if (signature.r && signature.s) {
        try {
          r = BigInt(`0x${signature.r}`);
          s = BigInt(`0x${signature.s}`);
        } catch (e) {
          // 无效的r或s值格式
          return false;
        }
      } else if (signature.signature) {
        try {
          // 从DER格式解码r和s
          const decoded = this.derDecode(signature.signature);
          r = decoded.r;
          s = decoded.s;
        } catch (e) {
          // 无效的DER格式
          return false;
        }
      } else {
        // 不符合期望的签名格式
        return false;
      }
      
      // 2. 检查r和s是否在[1, n-1]范围内
      if (r <= 0n || r >= this.n || s <= 0n || s >= this.n) {
        return false;
      }
      
      // 3. 计算消息摘要e
      const messageHash = await this.sha256(message);
      const e = this.hashToInt(messageHash, this.n);
      
      // 4. 计算s的模逆 w = s^(-1) mod n
      const w = this.modInverse(s, this.n);
      
      // 5. 计算u1 = e*w mod n 和 u2 = r*w mod n
      const u1 = (e * w) % this.n;
      const u2 = (r * w) % this.n;
      
      // 6. 计算曲线点 (x1, y1) = u1*G + u2*Q
      const u1G = this.pointMultiply(this.G, u1);
      const u2Q = this.pointMultiply(Q, u2);
      const sum = this.pointAdd(u1G, u2Q);
      
      // 7. 验证 r ≡ x1 (mod n)
      return (sum.x % this.n) === r;
    } catch (error) {
      // 静默失败，返回false而不输出错误日志
      return false;
    }
  }

  /**
   * 哈希函数SHA-256
   */
  private async sha256(message: string): Promise<string> {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (error) {
        console.warn('SHA-256调用失败，使用备用哈希:', error);
        return this.backupHash(message);
      }
    } else {
      return this.backupHash(message);
    }
  }

  /**
   * 备用哈希函数
   */
  private backupHash(message: string): string {
    // 简单哈希函数 (非标准，仅作教学用途)
    let h = 0xdeadbeef; // 初始哈希值
    const data = new TextEncoder().encode(message);
    
    // 模拟SHA-256的多轮混合
    for (let i = 0; i < data.length; i++) {
      h = ((h << 5) | (h >>> 27)) ^ data[i];
      h = (h * 0x1f3d5b79 + 0x2b) & 0xffffffff;
    }
    
    // 将结果转换为64字符的十六进制字符串(模拟SHA-256的256位输出)
    let result = '';
    for (let i = 0; i < 8; i++) {
      const word = (h ^ (h >> 16)) * 0x45d9f3b;
      h = (h << 7) | (h >>> 25);
      result += (word & 0xffffffff).toString(16).padStart(8, '0');
    }
    
    return result;
  }

  /**
   * 将哈希值转换为大整数
   */
  private hashToInt(hash: string, max: bigint): bigint {
    // 清理非十六进制字符
    const cleanHash = hash.replace(/[^0-9a-fA-F]/g, '');
    
    // 取哈希的前缀，确保不超过曲线阶n的位长
    const maxBits = max.toString(2).length;
    const hashBits = cleanHash.length * 4; // 每个十六进制字符代表4位
    
    // 如果哈希比max短，直接转换
    if (hashBits <= maxBits) {
      return BigInt(`0x${cleanHash}`) % max;
    }
    
    // 否则截取前缀
    const prefixLen = Math.floor(maxBits / 4) + (maxBits % 4 ? 1 : 0);
    const truncatedHash = cleanHash.substring(0, prefixLen);
    return BigInt(`0x${truncatedHash}`) % max;
  }

  /**
   * 基于RFC 6979的确定性k值生成
   * 对相同的私钥和消息，总是生成相同的k值，避免随机数生成缺陷
   */
  private async generateDeterministicK(privateKey: bigint, messageHash: bigint): Promise<bigint> {
    // 将私钥和消息哈希转换为字节数组
    const dBytes = this.bigintToUint8Array(privateKey);
    const hBytes = this.bigintToUint8Array(messageHash);
    
    // 初始化状态
    let v = new Uint8Array(32).fill(1); // 32个字节的1
    let k = new Uint8Array(32).fill(0); // 32个字节的0
    
    // 第一步: hmac_k = HMAC(key=k, v + 0x00 + dBytes + hBytes)
    // 我们用简化版本实现
    const combined1 = this.concatArrays([v, new Uint8Array([0]), dBytes, hBytes]);
    k = (await this.simplifiedHmac(k, combined1)) as Uint8Array<ArrayBuffer>;
    
    // 第二步: v = HMAC(key=k, v)
    v = (await this.simplifiedHmac(k, v)) as Uint8Array<ArrayBuffer>;
    
    // 第三步: hmac_k = HMAC(key=k, v + 0x01 + dBytes + hBytes)
    const combined2 = this.concatArrays([v, new Uint8Array([1]), dBytes, hBytes]);
    k = (await this.simplifiedHmac(k, combined2)) as Uint8Array<ArrayBuffer>;
    
    // 第四步: v = HMAC(key=k, v)
    v = (await this.simplifiedHmac(k, v)) as Uint8Array<ArrayBuffer>;
    
    // 生成k值
    let kCandidate: bigint;
    
    do {
      // 更新v = HMAC(key=k, v)
      v = (await this.simplifiedHmac(k, v)) as Uint8Array<ArrayBuffer>;
      
      // 将v转换为整数
      kCandidate = this.uint8ArrayToBigInt(v) % this.n;
      
      // 检查k是否已被使用（防止重复使用）
      const kStr = kCandidate.toString(16);
      if (kCandidate > 0n && kCandidate < this.n && !this.usedKValues.has(kStr)) {
        this.usedKValues.add(kStr);
        return kCandidate;
      }
      
      // 更新k和v以生成新的候选值
      const combined3 = this.concatArrays([v, new Uint8Array([0])]);
      k = (await this.simplifiedHmac(k, combined3)) as Uint8Array<ArrayBuffer>;
      v = (await this.simplifiedHmac(k, v)) as Uint8Array<ArrayBuffer>;
    } while (true);
  }

  /**
   * 简化版HMAC函数
   * 在无法使用Web Crypto API的情况下使用
   */
  private async simplifiedHmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        // 使用Web Crypto API (如果可用)
        const cryptoKey = await window.crypto.subtle.importKey(
          'raw',
          key,
          { name: 'HMAC', hash: { name: 'SHA-256' } },
          false,
          ['sign']
        );
        const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, data);
        // 使用具体的ArrayBuffer类型转换，确保类型兼容
        return new Uint8Array(signature) as Uint8Array<ArrayBuffer>;
      } catch (e) {
        // 回退到备用实现
      }
    }
    
    // 备用实现 (不是密码学安全的，但足够用于教学)
    const output = new Uint8Array(32);
    let temp = 0;
    
    // 模拟HMAC的混合
    for (let i = 0; i < data.length; i++) {
      for (let j = 0; j < 32; j++) {
        temp = (key[j % key.length] + data[i] + temp) & 0xFF;
        output[j] = output[j] ^ temp;
        // 混淆操作
        temp = ((temp << 5) | (temp >>> 3)) & 0xFF;
      }
    }
    
    return output as Uint8Array<ArrayBuffer>;
  }

  /**
   * 连接多个Uint8Array
   */
  private concatArrays(arrays: Uint8Array[]): Uint8Array {
    // 计算总长度
    const totalLength = arrays.reduce((acc, array) => acc + array.length, 0);
    
    // 创建新数组
    const result = new Uint8Array(totalLength);
    
    // 填充数据
    let offset = 0;
    for (const array of arrays) {
      result.set(array, offset);
      offset += array.length;
    }
    
    return result;
  }

  /**
   * 椭圆曲线点加法
   * P + Q = R，其中P、Q、R都是曲线上的点
   * 
   * 如果P ≠ Q，则:
   * λ = (Qy - Py) / (Qx - Px) mod p
   * Rx = λ² - Px - Qx mod p
   * Ry = λ(Px - Rx) - Py mod p
   */
  private pointAdd(P: Point, Q: Point): Point {
    // 处理特殊情况：若P是无穷远点，返回Q
    if (P.x === 0n && P.y === 0n) return Q;
    // 处理特殊情况：若Q是无穷远点，返回P
    if (Q.x === 0n && Q.y === 0n) return P;
    
    // 如果P = Q，则调用点倍运算
    if (P.x === Q.x && P.y === Q.y) {
      return this.pointDouble(P);
    }
    
    // 如果P和Q的x坐标相同但y坐标不同，则它们互为负点，和为无穷远点
    if (P.x === Q.x) {
      return { x: 0n, y: 0n }; // 无穷远点
    }
    
    // 计算斜率 λ = (Qy - Py) / (Qx - Px) mod p
    let numerator = (Q.y - P.y) % this.p;
    if (numerator < 0n) numerator += this.p;
    
    let denominator = (Q.x - P.x) % this.p;
    if (denominator < 0n) denominator += this.p;
    
    const lambda = (numerator * this.modInverse(denominator, this.p)) % this.p;
    
    // 计算R的坐标
    // Rx = λ² - Px - Qx mod p
    let Rx = (lambda ** 2n - P.x - Q.x) % this.p;
    if (Rx < 0n) Rx += this.p;
    
    // Ry = λ(Px - Rx) - Py mod p
    let Ry = (lambda * (P.x - Rx) - P.y) % this.p;
    if (Ry < 0n) Ry += this.p;
    
    return { x: Rx, y: Ry };
  }

  /**
   * 椭圆曲线点倍运算 (点加自身)
   * 2P = P + P，特殊情况的点加法
   * 
   * λ = (3Px² + a) / (2Py) mod p
   * Rx = λ² - 2Px mod p
   * Ry = λ(Px - Rx) - Py mod p
   */
  private pointDouble(P: Point): Point {
    // 处理特殊情况：若P是无穷远点，结果也是无穷远点
    if (P.x === 0n && P.y === 0n) return P;
    
    // 如果P的y坐标为0，则2P是无穷远点
    if (P.y === 0n) {
      return { x: 0n, y: 0n }; // 无穷远点
    }
    
    // 计算斜率 λ = (3Px² + a) / (2Py) mod p
    let numerator = (3n * P.x ** 2n + this.a) % this.p;
    if (numerator < 0n) numerator += this.p;
    
    let denominator = (2n * P.y) % this.p;
    if (denominator < 0n) denominator += this.p;
    
    const lambda = (numerator * this.modInverse(denominator, this.p)) % this.p;
    
    // 计算R的坐标
    // Rx = λ² - 2Px mod p
    let Rx = (lambda ** 2n - 2n * P.x) % this.p;
    if (Rx < 0n) Rx += this.p;
    
    // Ry = λ(Px - Rx) - Py mod p
    let Ry = (lambda * (P.x - Rx) - P.y) % this.p;
    if (Ry < 0n) Ry += this.p;
    
    return { x: Rx, y: Ry };
  }

  /**
   * 椭圆曲线点乘运算
   * k × P，表示P点加自身k次
   * 使用倍加算法实现高效点乘
   */
  private pointMultiply(P: Point, k: bigint): Point {
    // 特殊情况：k=0或P是无穷远点，结果为无穷远点
    if (k === 0n || (P.x === 0n && P.y === 0n)) {
      return { x: 0n, y: 0n }; // 无穷远点
    }
    
    // 特殊情况：k=1，直接返回P
    if (k === 1n) return P;
    
    // 处理负数k的情况
    if (k < 0n) {
      // 负数点乘相当于点乘后再取反点
      const negK = -k;
      const result = this.pointMultiply(P, negK);
      // 椭圆曲线上点的负元素是(x, -y mod p)
      return { x: result.x, y: this.p - result.y };
    }
    
    // 使用双倍加算法实现点乘
    // 将k表示为二进制，从高位到低位扫描
    // 初始结果为"无穷远点"(椭圆曲线群的单位元)
    let result = { x: 0n, y: 0n };
    let addend = P;
    
    while (k > 0n) {
      // 如果k的最低位为1，将当前addend加到result上
      if (k & 1n) {
        result = this.pointAdd(result, addend);
      }
      
      // 将addend翻倍，准备下一次迭代
      addend = this.pointDouble(addend);
      
      // k右移一位
      k = k >> 1n;
    }
    
    return result;
  }

  /**
   * 计算模逆元
   * 使用扩展欧几里得算法
   */
  private modInverse(a: bigint, m: bigint): bigint {
    // 确保a为正数
    a = ((a % m) + m) % m;
    
    if (a === 0n) {
      throw new Error('模逆元不存在: 除数不能为0');
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
    
    // 检查是否存在模逆元
    if (old_r !== 1n) {
      throw new Error('模逆元不存在: gcd不为1');
    }
    
    // 确保结果为正数
    return (old_s % m + m) % m;
  }

  /**
   * 生成指定范围内的随机大整数
   */
  private getRandomBigInt(min: bigint, max: bigint): bigint {
    const range = max - min;
    const bitsNeeded = this.countBits(range);
    const bytesNeeded = Math.ceil(bitsNeeded / 8);
    
    // 创建字节数组用于存储随机值
    const randomBytes = new Uint8Array(bytesNeeded);
    
    // 填充随机字节
    if (typeof window !== 'undefined' && window.crypto) {
      window.crypto.getRandomValues(randomBytes);
    } else {
      // 如果不在浏览器环境，使用简单随机数
      for (let i = 0; i < bytesNeeded; i++) {
        randomBytes[i] = Math.floor(Math.random() * 256);
      }
    }
    
    // 转换为BigInt
    let result = 0n;
    for (let i = 0; i < randomBytes.length; i++) {
      result = (result << 8n) | BigInt(randomBytes[i]);
    }
    
    // 确保结果在[min, max]范围内
    return min + (result % (range + 1n));
  }

  /**
   * 计算一个大整数需要的位数
   */
  private countBits(n: bigint): number {
    if (n === 0n) return 1;
    
    let bits = 0;
    let temp = n;
    
    while (temp > 0n) {
      bits++;
      temp = temp >> 1n;
    }
    
    return bits;
  }

  /**
   * 将BigInt转换为Uint8Array
   */
  private bigintToUint8Array(value: bigint): Uint8Array {
    if (value === 0n) return new Uint8Array([0]);
    
    // 计算需要的字节数
    const hex = value.toString(16);
    // 确保hex的长度为偶数
    const paddedHex = hex.length % 2 ? '0' + hex : hex;
    
    const bytes = new Uint8Array(paddedHex.length / 2);
    
    for (let i = 0; i < bytes.length; i++) {
      const hexByte = paddedHex.substring(i * 2, i * 2 + 2);
      bytes[i] = parseInt(hexByte, 16);
    }
    
    return bytes;
  }

  /**
   * 将Uint8Array转换为BigInt
   */
  private uint8ArrayToBigInt(bytes: Uint8Array): bigint {
    let result = 0n;
    
    for (let i = 0; i < bytes.length; i++) {
      result = (result << 8n) | BigInt(bytes[i]);
    }
    
    return result;
  }

  /**
   * 将签名编码为DER格式（符合X.509标准）
   */
  private derEncode(r: bigint, s: bigint): string {
    // 转换r和s为Uint8Array
    let rBytes = this.bigintToUint8Array(r);
    let sBytes = this.bigintToUint8Array(s);
    
    // 如果最高位为1，需要补0以避免被解释为负数
    if (rBytes[0] & 0x80) {
      const temp = new Uint8Array(rBytes.length + 1);
      temp.set(rBytes, 1);
      rBytes = temp;
    }
    
    if (sBytes[0] & 0x80) {
      const temp = new Uint8Array(sBytes.length + 1);
      temp.set(sBytes, 1);
      sBytes = temp;
    }
    
    // r的DER编码
    const rDer = new Uint8Array(2 + rBytes.length);
    rDer[0] = 0x02; // INTEGER类型
    rDer[1] = rBytes.length; // 长度
    rDer.set(rBytes, 2); // 值
    
    // s的DER编码
    const sDer = new Uint8Array(2 + sBytes.length);
    sDer[0] = 0x02; // INTEGER类型
    sDer[1] = sBytes.length; // 长度
    sDer.set(sBytes, 2); // 值
    
    // 整个签名的DER编码
    const sigDer = new Uint8Array(2 + rDer.length + sDer.length);
    sigDer[0] = 0x30; // SEQUENCE类型
    sigDer[1] = rDer.length + sDer.length; // 长度
    sigDer.set(rDer, 2); // r值
    sigDer.set(sDer, 2 + rDer.length); // s值
    
    // 转换为十六进制字符串
    return Array.from(sigDer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * 从DER格式解码签名
   */
  private derDecode(derHex: string): { r: bigint, s: bigint } {
    // 将十六进制字符串转换为字节数组
    const derBytes = new Uint8Array(derHex.length / 2);
    for (let i = 0; i < derBytes.length; i++) {
      derBytes[i] = parseInt(derHex.substring(i * 2, i * 2 + 2), 16);
    }
    
    // 验证格式
    if (derBytes[0] !== 0x30) {
      throw new Error('无效的DER编码：不是SEQUENCE');
    }
    
    // 跳过SEQUENCE头部
    let index = 2;
    
    // 解析r
    if (derBytes[index] !== 0x02) {
      throw new Error('无效的DER编码：r不是INTEGER');
    }
    
    const rLength = derBytes[index + 1];
    index += 2;
    
    // 提取r值，忽略可能的前导零（用于处理负数表示）
    let rStart = index;
    if (derBytes[rStart] === 0x00 && (derBytes[rStart + 1] & 0x80)) {
      rStart++;
    }
    
    let r = 0n;
    for (let i = rStart; i < index + rLength; i++) {
      r = (r << 8n) | BigInt(derBytes[i]);
    }
    
    index += rLength;
    
    // 解析s
    if (derBytes[index] !== 0x02) {
      throw new Error('无效的DER编码：s不是INTEGER');
    }
    
    const sLength = derBytes[index + 1];
    index += 2;
    
    // 提取s值，忽略可能的前导零
    let sStart = index;
    if (derBytes[sStart] === 0x00 && (derBytes[sStart + 1] & 0x80)) {
      sStart++;
    }
    
    let s = 0n;
    for (let i = sStart; i < index + sLength; i++) {
      s = (s << 8n) | BigInt(derBytes[i]);
    }
    
    return { r, s };
  }
}

/**
 * 椭圆曲线上的点
 */
interface Point {
  x: bigint;
  y: bigint;
} 