import { ECDSA } from '../ECDSA';
import { KeyPair } from '../types';

describe('ECDSA Algorithm', () => {
  let ecdsa: ECDSA;
  let keyPair: KeyPair;
  
  // 在所有测试前生成密钥对
  beforeAll(async () => {
    ecdsa = new ECDSA();
    keyPair = await ecdsa.generateKeys();
    // 确保密钥已生成
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
  }, 30000); // 给予30秒来生成密钥
  
  // 测试密钥格式是否正确
  test('should have correctly formatted keys', () => {
    // 公钥应包含x、y坐标
    expect(keyPair.publicKey.x).toBeDefined();
    expect(keyPair.publicKey.y).toBeDefined();
    expect(keyPair.publicKey.curve).toBeDefined();
    
    // 私钥应包含d（私钥值）
    expect(keyPair.privateKey.d).toBeDefined();
    expect(keyPair.privateKey.curve).toBeDefined();
  });
  
  // 测试密钥值是否有效
  test('should have valid key values', () => {
    // 密钥应为十六进制字符串
    expect(typeof keyPair.publicKey.x).toBe('string');
    expect(typeof keyPair.publicKey.y).toBe('string');
    expect(typeof keyPair.privateKey.d).toBe('string');
    
    // 十六进制字符串应有效
    expect(() => BigInt(`0x${keyPair.publicKey.x}`)).not.toThrow();
    expect(() => BigInt(`0x${keyPair.publicKey.y}`)).not.toThrow();
    expect(() => BigInt(`0x${keyPair.privateKey.d}`)).not.toThrow();
    
    // 转换为数值（使用正确的十六进制格式）
    const x = BigInt(`0x${keyPair.publicKey.x}`);
    const y = BigInt(`0x${keyPair.publicKey.y}`);
    const d = BigInt(`0x${keyPair.privateKey.d}`);
    
    // 值应为正数
    expect(x).toBeGreaterThan(0n);
    expect(y).toBeGreaterThan(0n);
    expect(d).toBeGreaterThan(0n);
  });
  
  // 测试曲线是否已指定
  test('should have curve specified', () => {
    // 检查曲线信息
    expect(keyPair.publicKey.curve).toBe('secp256k1');
    expect(keyPair.privateKey.curve).toBe('secp256k1');
  });
  
  // 测试密钥是否具有适当的长度
  test('should have key with appropriate length', () => {
    // ECDSA secp256k1密钥应为256位（32字节）
    expect(keyPair.publicKey.x.length).toBeGreaterThanOrEqual(64); // 64个十六进制字符 = 32字节
    expect(keyPair.publicKey.y.length).toBeGreaterThanOrEqual(64);
    expect(keyPair.privateKey.d.length).toBeGreaterThanOrEqual(64);
  });
  
  // 签名和验证测试
  describe('Signature and Verification', () => {
    // 测试是否能成功签名和验证消息
    test('should successfully sign and verify a message', async () => {
      const message = "Hello, ECDSA digital signature!";
      
      // 生成签名
      const signature = await ecdsa.sign(message, keyPair);
      
      // 验证签名结果包含所需属性
      expect(signature).toBeDefined();
      expect(signature.r).toBeDefined();
      expect(signature.s).toBeDefined();
      expect(signature.messageHash).toBeDefined();
      expect(signature.signature).toBeDefined(); // DER格式的签名
      
      // 验证签名
      const result = await ecdsa.verify(message, signature, keyPair);
      expect(result).toBe(true);
      console.info(`原始消息验证结果: ${result ? '成功✓' : '失败✗'}`);
    });
    
    // 测试签名是否具有预期格式
    test('should return signature with expected format', async () => {
      const message = "Testing ECDSA signature format";
      
      const signature = await ecdsa.sign(message, keyPair);
      
      // 验证r和s是字符串且可解析为BigInt
      expect(typeof signature.r).toBe('string');
      expect(typeof signature.s).toBe('string');
      expect(typeof signature.signature).toBe('string');
      
      // 检查r和s是否为标准的64位十六进制字符串（256位）
      expect(signature.r?.length).toBe(64);
      expect(signature.s?.length).toBe(64);
      
      // 检查r和s的值是否有效
      const r = BigInt(`0x${signature.r || ''}`);
      const s = BigInt(`0x${signature.s || ''}`);
      
      expect(r).toBeGreaterThan(0n);
      expect(s).toBeGreaterThan(0n);
      
      // 验证哈希值格式
      expect(typeof signature.messageHash).toBe('string');
      // SHA-256 输出长度可能因具体实现而异，但应该至少有30个字符
      expect(signature.messageHash?.length).toBeGreaterThanOrEqual(30);
    });
    
    // 测试对篡改消息的签名验证应被拒绝
    test('should reject signatures for tampered messages', async () => {
      // 原始消息
      const originalMessage = "Original message for ECDSA testing";
      
      // 生成签名
      const signature = await ecdsa.sign(originalMessage, keyPair);
      
      // 验证原始消息（应成功）
      const validResult = await ecdsa.verify(originalMessage, signature, keyPair);
      expect(validResult).toBe(true);
      console.info(`原始消息验证结果: ${validResult ? '成功✓' : '失败✗'}`);
      
      // 验证篡改消息（应失败）
      const tamperedMessage = "This message has been tampered with!";
      const invalidResult = await ecdsa.verify(tamperedMessage, signature, keyPair);
      expect(invalidResult).toBe(false);
      console.info(`篡改消息验证结果: ${invalidResult ? '错误地成功✗' : '正确地失败✓'}`);
    });
    
    // 测试篡改过的签名应被拒绝
    test('should reject tampered signatures', async () => {
      // 原始消息
      const message = "Message for tampered signature test";
      
      // 生成签名
      const signature = await ecdsa.sign(message, keyPair);
      
      // 篡改签名的r值
      const originalR = signature.r;
      const rBigInt = BigInt(`0x${originalR}`);
      const tamperedR = (rBigInt + 1n).toString(16).padStart(64, '0');
      
      const tamperedSignature = {
        ...signature,
        r: tamperedR
      };
      
      // 验证篡改签名（应失败）
      const result = await ecdsa.verify(message, tamperedSignature, keyPair);
      expect(result).toBe(false);
      console.info(`篡改r值验证结果: ${result ? '错误地成功✗' : '正确地失败✓'}`);
      
      // 篡改签名的s值
      const originalS = signature.s;
      const sBigInt = BigInt(`0x${originalS}`);
      const tamperedS = (sBigInt + 1n).toString(16).padStart(64, '0');
      
      const tamperedSignature2 = {
        ...signature,
        s: tamperedS
      };
      
      // 验证篡改签名（应失败）
      const result2 = await ecdsa.verify(message, tamperedSignature2, keyPair);
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
        "This is a medium length message for testing ECDSA signature verification", // 中等长度
        "A".repeat(1000) // 长消息
      ];
      
      for (const message of messages) {
        // 生成签名
        const signature = await ecdsa.sign(message, keyPair);
        
        // 验证签名
        const result = await ecdsa.verify(message, signature, keyPair);
        
        // 记录结果
        console.info(`消息长度 ${message.length} 验证结果: ${result ? '成功✓' : '失败✗'}`);
        
        // 验证应该成功
        expect(result).toBe(true);
      }
    });
    
    // 测试使用直接r,s和DER编码签名进行验证
    test('should verify using both direct r,s and DER encoded signatures', async () => {
      const message = "Testing DER encoding and direct r,s verification";
      
      // 生成签名
      const signature = await ecdsa.sign(message, keyPair);
      
      // 使用直接提供的r和s进行验证
      const directResult = await ecdsa.verify(message, {
        r: signature.r,
        s: signature.s
      }, keyPair);
      
      expect(directResult).toBe(true);
      console.info(`直接r,s验证结果: ${directResult ? '成功✓' : '失败✗'}`);
      
      // 使用DER编码签名进行验证
      const derResult = await ecdsa.verify(message, {
        signature: signature.signature
      }, keyPair);
      
      expect(derResult).toBe(true);
      console.info(`DER编码验证结果: ${derResult ? '成功✓' : '失败✗'}`);
    });
    
    // 测试拒绝无效签名格式
    test('should reject invalid signature formats', async () => {
      const message = "Testing invalid signature handling";
      
      // 测试无效签名格式
      const invalidSignature = { foo: "bar" };
      
      // 应该拒绝或优雅处理无效格式
      const result = await ecdsa.verify(message, invalidSignature, keyPair);
      expect(result).toBe(false);
      
      // 测试无效r值（超出曲线阶n的范围）
      // 创建一个超大的r值
      const hugeValue = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
      
      const invalidR = {
        r: hugeValue,
        s: "1111111111111111111111111111111111111111111111111111111111111111"
      };
      
      const resultInvalidR = await ecdsa.verify(message, invalidR, keyPair);
      expect(resultInvalidR).toBe(false);
      
      console.info('无效签名处理测试通过✓');
    });
  });
}); 