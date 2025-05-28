declare module 'elliptic' {
  export interface EC {
    genKeyPair(): any;
    keyFromPublic(publicKey: string, format: string): any;
  }
 
  export function ec(curve: string): EC;
} 