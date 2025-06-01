import { EncryptionAlgorithm, KeyPair, EncryptionResult } from './encryption-types';
import { RSAEncryption } from './RSAEncryption';
import { ElGamalEncryption } from './ElGamalEncryption';
import { ECCEncryption } from './ECCEncryption';

// 导出类型，方便其他模块使用
export type { KeyPair, EncryptionResult, EncryptionAlgorithm };

/**
 * 加密算法工厂类，用于获取指定的加密算法实例
 */
export class EncryptionAlgorithmFactory {
  private static instances: Record<string, EncryptionAlgorithm> = {};

  /**
   * 获取所有可用的加密算法列表
   * @returns 加密算法名称数组
   */
  static getAvailableAlgorithms(): string[] {
    return ['RSA', 'ElGamal', 'ECC'];
  }

  /**
   * 获取指定算法的实例
   * @param algorithm 算法名称: 'RSA', 'ElGamal', 或 'ECC'
   * @returns 算法实例
   */
  static getAlgorithm(algorithm: string): EncryptionAlgorithm {
    const algorithmName = algorithm.toUpperCase();
    
    if (!this.instances[algorithmName]) {
      switch (algorithmName) {
        case 'RSA':
          this.instances[algorithmName] = new RSAEncryption();
          break;
        case 'ELGAMAL':
          this.instances[algorithmName] = new ElGamalEncryption();
          break;
        case 'ECC':
          this.instances[algorithmName] = new ECCEncryption();
          break;
        default:
          throw new Error(`不支持的算法: ${algorithm}`);
      }
    }
    
    return this.instances[algorithmName];
  }
} 