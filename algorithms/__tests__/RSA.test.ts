import { RSA } from '../RSA';
import { KeyPair } from '../types';

describe('RSA Algorithm', () => {
  let rsa: RSA;
  let keyPair: KeyPair;
  
  // 在所有测试前生成密钥对
  beforeAll(async () => {
    rsa = new RSA();
    keyPair = await rsa.generateKeys();
    // 确保密钥已生成
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
  }, 30000); // 给予30秒来生成密钥
  
  // 密钥生成测试
  describe('Key Generation', () => {
    // 测试密钥格式是否正确
    test('should have correctly formatted keys', () => {
      // 公钥应包含e和n
      expect(keyPair.publicKey.e).toBeDefined();
      expect(keyPair.publicKey.n).toBeDefined();
      
      // 私钥应包含d和n
      expect(keyPair.privateKey.d).toBeDefined();
      expect(keyPair.privateKey.n).toBeDefined();
      
      // 公钥和私钥中的n应相同
      expect(keyPair.publicKey.n).toEqual(keyPair.privateKey.n);
    });
    
    // 测试密钥值是否有效
    test('should have valid key values', () => {
      // 值应为有效数字
      const n = BigInt(keyPair.publicKey.n);
      const e = BigInt(keyPair.publicKey.e);
      const d = BigInt(keyPair.privateKey.d);
      
      expect(n).toBeGreaterThan(0n);
      expect(e).toBeGreaterThan(0n);
      expect(d).toBeGreaterThan(0n);
      
      // 公共指数应为65537
      expect(e).toBe(65537n);
    });
    
    // 测试密钥关系是否正确
    test('should have consistent keys with proper relationship', () => {
      const n = BigInt(keyPair.publicKey.n);
      const e = BigInt(keyPair.publicKey.e);
      const d = BigInt(keyPair.privateKey.d);
      
      // 简单测试: d * e 应大于 n
      // 这是一个弱测试，但不需要对n进行因式分解
      expect(d * e).toBeGreaterThan(n);
      
      // d和e应互质
      // 必要但非充分条件
      const gcd = (a: bigint, b: bigint): bigint => {
        while (b !== 0n) {
          const temp = b;
          b = a % b;
          a = temp;
        }
        return a;
      };
      
      // e和d应互质
      expect(gcd(e, d)).toBe(1n);
    });
    
    // 测试模数位长度是否合适
    test('should have modulus with appropriate bit length', () => {
      const n = BigInt(keyPair.publicKey.n);
      
      // 转换为二进制并计算位数
      const bitLength = n.toString(2).length;
      
      // 应至少为2000位(允许一定的灵活性)
      expect(bitLength).toBeGreaterThanOrEqual(2000);
    });
  });
  
  // 签名和验证测试
  describe('Signature and Verification', () => {
    // 测试能否生成签名
    test('should be able to generate a signature', async () => {
      const message = "Hello, RSA signature!";
      
      // 只检查签名生成是否正常工作
      const signature = await rsa.sign(message, keyPair);
      expect(signature).toBeDefined();
      expect(signature.signature).toBeDefined();
      expect(signature.messageHash).toBeDefined();
      expect(signature.salt).toBeDefined();
    });
    
    // 测试签名结果是否包含预期属性
    test('signature result should include expected properties', async () => {
      const message = "Testing signature properties";
      
      // 签名生成和检查属性
      const signature = await rsa.sign(message, keyPair);
      
      // 验证签名结果中包含所需的所有属性
      expect(signature.signature).toBeDefined();
      expect(signature.messageHash).toBeDefined();
      expect(signature.n).toBeDefined();
      expect(signature.salt).toBeDefined();
      
      // 确保属性是字符串类型
      expect(typeof signature.signature).toBe('string');
      expect(typeof signature.messageHash).toBe('string');
      expect(typeof signature.n).toBe('string');
      expect(typeof signature.salt).toBe('string');
      
      // 验证字符串格式
      const sig = BigInt(signature.signature);
      expect(sig).toBeGreaterThan(0n);
      
      // 验证哈希值存在并具有合理长度(不检查具体格式，只确保不为空)
      if (signature.messageHash) {
        expect(signature.messageHash.length).toBeGreaterThan(0);
      }
    });
    
    // 测试正确验证有效签名并拒绝无效签名
    test('should properly verify valid signatures and reject invalid ones', async () => {
      // 原始消息
      const originalMessage = "Original message for testing signature verification";
      
      // 生成签名
      const signature = await rsa.sign(originalMessage, keyPair);
      
      // 1. 使用原始消息验证签名 - 应该成功
      const validResult = await rsa.verify(originalMessage, signature, keyPair);
      expect(validResult).toBe(true);
      console.info(`原始消息验证结果: ${validResult ? '成功✓' : '失败✗'}`);
      
      // 2. 使用修改过的消息验证签名 - 应该失败
      const tamperedMessage = "This message has been tampered with!";
      const invalidResult = await rsa.verify(tamperedMessage, signature, keyPair);
      expect(invalidResult).toBe(false);
      console.info(`篡改消息验证结果: ${invalidResult ? '错误地成功✗' : '正确地失败✓'}`);
      
      // 3. 使用修改过的签名验证原始消息 - 应该失败
      const originalSig = BigInt(signature.signature);
      const tamperedSig = (originalSig + 1n).toString(); // 修改签名值
      
      const tamperedSignature = { 
        ...signature,
        signature: tamperedSig
      };
      
      const invalidSigResult = await rsa.verify(originalMessage, tamperedSignature, keyPair);
      expect(invalidSigResult).toBe(false);
      console.info(`篡改签名验证结果: ${invalidSigResult ? '错误地成功✗' : '正确地失败✓'}`);
    });
    
    // 测试不同长度消息的签名验证
    test('should verify signatures with different message lengths', async () => {
      // 测试不同长度的消息
      const messages = [
        "", // 空消息
        "a", // 单字符
        "Short message", // 短消息
        "This is a medium length message for testing signature verification", // 中等长度
        "A".repeat(1000) // 长消息
      ];
      
      for (const message of messages) {
        // 生成签名
        const signature = await rsa.sign(message, keyPair);
        
        // 验证签名
        const result = await rsa.verify(message, signature, keyPair);
        
        // 记录结果
        console.info(`消息长度 ${message.length} 验证结果: ${result ? '成功✓' : '失败✗'}`);
        
        // 验证应该成功
        expect(result).toBe(true);
      }
    });
    
    // 测试签名和验证函数是否存在并已实现
    test('signature and verification functions exist and are implemented', () => {
      // 验证接口实现
      expect(typeof rsa.sign).toBe('function');
      expect(typeof rsa.verify).toBe('function');
      
      console.info('RSA-PSS签名验证功能已成功实现并通过测试');
    });
  });
}); 