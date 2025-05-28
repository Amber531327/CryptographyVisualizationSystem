import { RSA } from './RSA';
import { DSA } from './DSA';
import { ECDSA } from './ECDSA';
import { CryptoAlgorithm } from './types';

export type { KeyPair, SignatureResult } from './types';

/**
 * 算法工厂类，用于获取指定的签名算法实例
 */
export class AlgorithmFactory {
  private static instances: Record<string, CryptoAlgorithm> = {};

  /**
   * 获取指定算法的实例
   * @param algorithm 算法名称: 'RSA', 'DSA', 或 'ECDSA'
   * @returns 算法实例
   */
  static getAlgorithm(algorithm: string): CryptoAlgorithm {
    const algorithmName = algorithm.toUpperCase();
    
    if (!this.instances[algorithmName]) {
      switch (algorithmName) {
        case 'RSA':
          this.instances[algorithmName] = new RSA();
          break;
        case 'DSA':
          this.instances[algorithmName] = new DSA();
          break;
        case 'ECDSA':
          this.instances[algorithmName] = new ECDSA();
          break;
        default:
          throw new Error(`不支持的算法: ${algorithm}`);
      }
    }
    
    return this.instances[algorithmName];
  }
} 