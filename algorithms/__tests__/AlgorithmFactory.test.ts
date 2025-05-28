import { AlgorithmFactory } from '../index';
import { RSA } from '../RSA';
import { DSA } from '../DSA';
import { ECDSA } from '../ECDSA';
import { CryptoAlgorithm } from '../types';

describe('AlgorithmFactory', () => {
  // 测试应当返回RSA实例
  test('should return RSA instance', () => {
    const instance = AlgorithmFactory.getAlgorithm('RSA');
    expect(instance).toBeInstanceOf(RSA);
  });
  
  // 测试应当返回DSA实例
  test('should return DSA instance', () => {
    const instance = AlgorithmFactory.getAlgorithm('DSA');
    expect(instance).toBeInstanceOf(DSA);
  });
  
  // 测试应当返回ECDSA实例
  test('should return ECDSA instance', () => {
    const instance = AlgorithmFactory.getAlgorithm('ECDSA');
    expect(instance).toBeInstanceOf(ECDSA);
  });
  
  // 测试算法名称应不区分大小写
  test('should be case-insensitive', () => {
    const instance1 = AlgorithmFactory.getAlgorithm('rsa');
    const instance2 = AlgorithmFactory.getAlgorithm('Rsa');
    
    expect(instance1).toBeInstanceOf(RSA);
    expect(instance2).toBeInstanceOf(RSA);
  });
  
  // 测试重复调用应返回相同实例
  test('should return the same instance on repeated calls', () => {
    const instance1 = AlgorithmFactory.getAlgorithm('RSA');
    const instance2 = AlgorithmFactory.getAlgorithm('RSA');
    
    expect(instance1).toBe(instance2); // 相同对象引用
  });
  
  // 测试不支持的算法应抛出错误
  test('should throw error for unsupported algorithm', () => {
    expect(() => {
      AlgorithmFactory.getAlgorithm('UnsupportedAlgorithm');
    }).toThrow('不支持的算法: UnsupportedAlgorithm');
  });
  
  // 测试每个算法实例都应实现CryptoAlgorithm接口
  test('each algorithm instance should implement CryptoAlgorithm interface', () => {
    const algorithms = ['RSA', 'DSA', 'ECDSA'];
    
    for (const algo of algorithms) {
      const instance = AlgorithmFactory.getAlgorithm(algo);
      
      // 检查接口实现
      expect(typeof instance.generateKeys).toBe('function');
      expect(typeof instance.sign).toBe('function');
      expect(typeof instance.verify).toBe('function');
    }
  });
}); 