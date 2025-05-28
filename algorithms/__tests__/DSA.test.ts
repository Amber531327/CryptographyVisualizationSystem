import { DSA } from '../DSA';
import { KeyPair } from '../types';

describe('DSA Algorithm', () => {
  let dsa: DSA;
  let keyPair: KeyPair;
  
  // 在所有测试前生成密钥对
  beforeAll(async () => {
    dsa = new DSA();
    keyPair = await dsa.generateKeys();
    // 确保密钥已生成
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
  }, 60000); // DSA密钥生成可能需要更长时间，允许60秒
  
  // 测试密钥是否格式正确
  test('should have correctly formatted keys', () => {
    // 公钥
    expect(keyPair.publicKey.p).toBeDefined();
    expect(keyPair.publicKey.q).toBeDefined();
    expect(keyPair.publicKey.g).toBeDefined();
    expect(keyPair.publicKey.y).toBeDefined();
    
    // 私钥
    expect(keyPair.privateKey.x).toBeDefined();
  });
  
  // 测试公钥中的域参数是否相同
  test('should have same domain parameters in publicKey', () => {
    // p, q 和 g 参数应共享
    const publicP = keyPair.publicKey.p;
    const publicQ = keyPair.publicKey.q;
    const publicG = keyPair.publicKey.g;
    
    expect(publicP).toBeDefined();
    expect(publicQ).toBeDefined();
    expect(publicG).toBeDefined();
  });
  
  // 测试参数值是否有效
  test('should have valid parameter values', () => {
    // 值应为有效的BigInt对象
    expect(typeof keyPair.publicKey.p).toBe('bigint');
    expect(typeof keyPair.publicKey.q).toBe('bigint');
    expect(typeof keyPair.publicKey.g).toBe('bigint');
    expect(typeof keyPair.publicKey.y).toBe('bigint');
    expect(typeof keyPair.privateKey.x).toBe('bigint');
    
    // 直接使用BigInt值
    const p = keyPair.publicKey.p;
    const q = keyPair.publicKey.q;
    const g = keyPair.publicKey.g;
    const y = keyPair.publicKey.y;
    const x = keyPair.privateKey.x;
    
    expect(p).toBeGreaterThan(0n);
    expect(q).toBeGreaterThan(0n);
    expect(g).toBeGreaterThan(0n);
    expect(y).toBeGreaterThan(0n);
    expect(x).toBeGreaterThan(0n);
    
    // p应大于q
    expect(p).toBeGreaterThan(q);
    
    // g应小于p
    expect(g).toBeLessThan(p);
    
    // y应小于p
    expect(y).toBeLessThan(p);
  });
  
  // 测试参数是否具有适当的位长度
  test('should have parameters with appropriate bit length', () => {
    // 直接使用BigInt值
    const p = keyPair.publicKey.p;
    const q = keyPair.publicKey.q;
    
    // 转换为二进制并计算位数
    const pBitLength = p.toString(2).length;
    const qBitLength = q.toString(2).length;
    
    // p至少应为1024位
    expect(pBitLength).toBeGreaterThanOrEqual(1024);
    
    // q至少应为160位
    expect(qBitLength).toBeGreaterThanOrEqual(160);
  });
  
  // 签名和验证测试
  describe('Signature and Verification', () => {
    // 测试是否能成功签名和验证消息
    test('should successfully sign and verify a message', async () => {
      const message = "Hello, DSA digital signature!";
      
      // 生成签名
      const signature = await dsa.sign(message, keyPair);
      
      // 验证签名结果包含所需属性
      expect(signature).toBeDefined();
      expect(signature.r).toBeDefined();
      expect(signature.s).toBeDefined();
      expect(signature.messageHash).toBeDefined();
      
      // 验证签名
      const result = await dsa.verify(message, signature, keyPair);
      expect(result).toBe(true);
      console.info(`原始消息验证结果: ${result ? '成功✓' : '失败✗'}`);
    });
    
    // 测试签名是否具有预期格式
    test('should return signature with expected format', async () => {
      const message = "Testing DSA signature format";
      
      const signature = await dsa.sign(message, keyPair);
      
      // 验证r和s是字符串且可解析为BigInt
      expect(typeof signature.r).toBe('string');
      expect(typeof signature.s).toBe('string');
      
      const r = BigInt(signature.r || '0');
      const s = BigInt(signature.s || '0');
      
      expect(r).toBeGreaterThan(0n);
      expect(s).toBeGreaterThan(0n);
      
      // 验证哈希值格式
      expect(typeof signature.messageHash).toBe('string');
      
      // 验证包含DSA参数位长信息
      expect(signature.pBits).toBeDefined();
      expect(signature.qBits).toBeDefined();
    });
    
    // 测试对篡改消息的签名验证应被拒绝
    test('should reject signatures for tampered messages', async () => {
      // 原始消息
      const originalMessage = "Original message for DSA testing";
      
      // 生成签名
      const signature = await dsa.sign(originalMessage, keyPair);
      
      // 验证原始消息（应成功）
      const validResult = await dsa.verify(originalMessage, signature, keyPair);
      expect(validResult).toBe(true);
      console.info(`原始消息验证结果: ${validResult ? '成功✓' : '失败✗'}`);
      
      // 验证篡改消息（应失败）
      const tamperedMessage = "This message has been tampered with!";
      const invalidResult = await dsa.verify(tamperedMessage, signature, keyPair);
      expect(invalidResult).toBe(false);
      console.info(`篡改消息验证结果: ${invalidResult ? '错误地成功✗' : '正确地失败✓'}`);
    });
    
    // 测试篡改过的签名应被拒绝
    test('should reject tampered signatures', async () => {
      // 原始消息
      const message = "Message for tampered signature test";
      
      // 生成签名
      const signature = await dsa.sign(message, keyPair);
      
      // 篡改签名的r值
      const originalR = BigInt(signature.r || '0');
      const tamperedR = (originalR + 1n).toString();
      
      const tamperedSignature = {
        ...signature,
        r: tamperedR
      };
      
      // 验证篡改签名（应失败）
      const result = await dsa.verify(message, tamperedSignature, keyPair);
      expect(result).toBe(false);
      console.info(`篡改r值验证结果: ${result ? '错误地成功✗' : '正确地失败✓'}`);
      
      // 篡改签名的s值
      const originalS = BigInt(signature.s || '0');
      const tamperedS = (originalS + 1n).toString();
      
      const tamperedSignature2 = {
        ...signature,
        s: tamperedS
      };
      
      // 验证篡改签名（应失败）
      const result2 = await dsa.verify(message, tamperedSignature2, keyPair);
      expect(result2).toBe(false);
      console.info(`篡改s值验证结果: ${result2 ? '错误地成功✗' : '正确地失败✓'}`);
    });
    
    // 测试不同长度消息的签名验证
    test('should verify signatures with different message lengths', async () => {
      // 测试不同长度的消息
      const messages = [
        "", // 空消息
        "a", // 单字符
        "Short message", // 短消息
        "This is a medium length message for testing DSA signature verification", // 中等长度
        "A".repeat(1000) // 长消息
      ];
      
      for (const message of messages) {
        // 生成签名
        const signature = await dsa.sign(message, keyPair);
        
        // 验证签名
        const result = await dsa.verify(message, signature, keyPair);
        
        // 记录结果
        console.info(`消息长度 ${message.length} 验证结果: ${result ? '成功✓' : '失败✗'}`);
        
        // 验证应该成功
        expect(result).toBe(true);
      }
    });
    
    // 测试无效的r或s值的签名应被拒绝
    test('should reject signatures with invalid r or s values', async () => {
      const message = "Testing invalid signature components";
      const signature = await dsa.sign(message, keyPair);
      
      // 测试r=0（应该失败）
      const invalidR1 = {
        ...signature,
        r: "0"
      };
      expect(await dsa.verify(message, invalidR1, keyPair)).toBe(false);
      
      // 测试r=q（应该失败，r应小于q）
      const q = keyPair.publicKey.q.toString();
      const invalidR2 = {
        ...signature,
        r: q
      };
      expect(await dsa.verify(message, invalidR2, keyPair)).toBe(false);
      
      // 测试s=0（应该失败）
      const invalidS1 = {
        ...signature,
        s: "0"
      };
      expect(await dsa.verify(message, invalidS1, keyPair)).toBe(false);
      
      // 测试s=q（应该失败，s应小于q）
      const invalidS2 = {
        ...signature,
        s: q
      };
      expect(await dsa.verify(message, invalidS2, keyPair)).toBe(false);
      
      console.info('无效签名分量验证测试通过✓');
    });
  });
}); 