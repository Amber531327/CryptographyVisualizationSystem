import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import ParticleBackground from '../components/ParticleBackground';
import Link from 'next/link';
import { EncryptionAlgorithmFactory, KeyPair, EncryptionResult } from '../algorithms';

export default function PublicKeyEncryptionPage() {
  // 算法选择状态
  const [algorithm, setAlgorithm] = useState('RSA');
  // 消息状态
  const [message, setMessage] = useState('');
  // 加密结果状态
  const [encryptionResult, setEncryptionResult] = useState<EncryptionResult | null>(null);
  // 解密结果状态
  const [decryptedMessage, setDecryptedMessage] = useState<string | null>(null);
  // 当前密钥状态
  const [currentKeys, setCurrentKeys] = useState<KeyPair | null>(null);
  // 动画状态
  const [animation, setAnimation] = useState<string | null>(null);
  // 状态提示
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  // 加载状态
  const [isLoading, setIsLoading] = useState(false);

  // 获取可用的加密算法
  const availableAlgorithms = EncryptionAlgorithmFactory.getAvailableAlgorithms();

  /**
   * 生成密钥对
   */
  const generateKeys = async () => {
    try {
      setIsLoading(true);
      setStatusMessage('正在生成密钥...');
      
      // 获取选定的加密算法
      const encryptionAlgorithm = EncryptionAlgorithmFactory.getAlgorithm(algorithm);
      
      // 生成新的密钥对
      const newKeys = await encryptionAlgorithm.generateKeys();
      setCurrentKeys(newKeys);
      
      // 设置动画状态和提示信息
      setAnimation('keys-generated');
      setStatusMessage('密钥生成成功，可以继续加密消息');
      
      // 重置加密和解密结果
      setEncryptionResult(null);
      setDecryptedMessage(null);
    } catch (error) {
      console.error('密钥生成错误:', error);
      setStatusMessage('密钥生成失败，请重试');
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * 加密消息
   */
  const encryptMessage = async () => {
    if (!message) {
      setStatusMessage('请输入要加密的消息');
      return;
    }
    
    if (!currentKeys) {
      setStatusMessage('请先生成密钥对');
      return;
    }
    
    try {
      setIsLoading(true);
      setStatusMessage('正在加密消息...');
      
      // 获取选定的加密算法
      const encryptionAlgorithm = EncryptionAlgorithmFactory.getAlgorithm(algorithm);
      
      // 使用公钥加密消息
      const result = await encryptionAlgorithm.encrypt(message, currentKeys.publicKey);
      setEncryptionResult(result);
      
      // 设置动画状态和提示信息
      setAnimation('message-encrypted');
      setStatusMessage('消息加密成功，可以继续解密');
      
      // 重置解密结果
      setDecryptedMessage(null);
    } catch (error) {
      console.error('加密错误:', error);
      setStatusMessage('加密失败，请重试');
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * 解密消息
   */
  const decryptMessage = async () => {
    if (!encryptionResult) {
      setStatusMessage('请先加密消息');
      return;
    }
    
    if (!currentKeys) {
      setStatusMessage('密钥丢失，请重新生成密钥');
      return;
    }
    
    try {
      setIsLoading(true);
      setStatusMessage('正在解密消息...');
      
      // 获取选定的加密算法
      const encryptionAlgorithm = EncryptionAlgorithmFactory.getAlgorithm(algorithm);
      
      // 使用私钥解密消息
      const decrypted = await encryptionAlgorithm.decrypt(encryptionResult, currentKeys.privateKey);
      setDecryptedMessage(decrypted);
      
      // 验证解密结果
      const isSuccess = decrypted === message;
      
      // 设置动画状态和提示信息
      setAnimation('message-decrypted');
      if (isSuccess) {
        setStatusMessage('消息解密成功，与原始消息匹配');
      } else {
        console.warn('解密结果与原始消息不匹配:', { 
          original: message, 
          decrypted: decrypted,
          isSimulated: encryptionResult.metadata?.isSimulated
        });
        setStatusMessage('消息解密成功，但结果与原始消息不匹配');
      }
    } catch (error) {
      console.error('解密错误:', error);
      setStatusMessage('解密失败，请重试');
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * 重置所有状态
   */
  const resetAll = () => {
    setMessage('');
    setCurrentKeys(null);
    setEncryptionResult(null);
    setDecryptedMessage(null);
    setAnimation(null);
    setStatusMessage(null);
  };

  /**
   * 获取当前算法的描述信息
   */
  const getCurrentAlgorithmDescription = () => {
    try {
      const encryptionAlgorithm = EncryptionAlgorithmFactory.getAlgorithm(algorithm);
      return encryptionAlgorithm.description;
    } catch (e) {
      return '未找到算法描述';
    }
  };

  /**
   * 格式化JSON显示
   */
  const formatJSON = (obj: any) => {
    try {
      return JSON.stringify(obj, null, 2);
    } catch (e) {
      return String(obj);
    }
  };

  /**
   * 截断长字符串
   */
  const truncateString = (str: string, maxLength: number = 100) => {
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength / 2) + '...' + str.substring(str.length - maxLength / 2);
  };

  return (
    <div className="container">
      {/* 添加粒子背景 */}
      <ParticleBackground />
      
      {/* 页面标题 */}
      <h1 className="title">
        公钥加密可视化系统
      </h1>
      
      {/* 返回主页按钮 */}
      <div className="back-to-home">
        <Link href="/" className="nav-button">
          返回首页
        </Link>
      </div>
      
      <div className="main-content encryption-page">
        {/* 算法选择器 */}
        <div className="algorithm-selector">
          {availableAlgorithms.map(algo => (
            <button
              key={algo}
              className={`algorithm-button ${algorithm === algo ? 'selected' : ''}`}
              onClick={() => {
                setAlgorithm(algo);
                resetAll();
              }}
            >
              {algo}
            </button>
          ))}
        </div>
        
        {/* 算法描述 */}
        <motion.div 
          className="algorithm-description"
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <p>{getCurrentAlgorithmDescription()}</p>
        </motion.div>

        {/* 加密操作区域 */}
        <div className="encryption-container">
          {/* 操作面板 */}
          <div className="control-panel">
            <h2>操作面板</h2>
            
            {/* 消息输入 - Now step 1 */}
            <div className="control-group">
              <h3>步骤 1: 输入消息</h3>
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="输入要加密的消息..."
                rows={4}
                disabled={isLoading}
              />
            </div>
            
            {/* 密钥生成 - Now step 2 */}
            <div className="control-group">
              <h3>步骤 2: 密钥生成</h3>
              <button 
                className="action-button" 
                onClick={generateKeys}
                disabled={!message || isLoading}
              >
                {isLoading && animation === 'keys-generated' ? '生成中...' : '生成密钥对'}
              </button>
            </div>
            
            {/* 消息加密 - Now step 3 */}
            <div className="control-group">
              <h3>步骤 3: 消息加密</h3>
              <button 
                className="action-button"
                onClick={encryptMessage}
                disabled={!currentKeys || !message || isLoading}
              >
                {isLoading && animation === 'message-encrypted' ? '加密中...' : '加密消息'}
              </button>
            </div>
            
            {/* 消息解密 - Now step 4 */}
            <div className="control-group">
              <h3>步骤 4: 消息解密</h3>
              <button 
                className="action-button"
                onClick={decryptMessage}
                disabled={!encryptionResult || isLoading}
              >
                {isLoading && animation === 'message-decrypted' ? '解密中...' : '解密消息'}
              </button>
            </div>
            
            {/* 状态信息 */}
            {statusMessage && (
              <div className={`status-message ${animation}`}>
                {statusMessage}
              </div>
            )}
            
            {/* 重置按钮 */}
            <button 
              className="reset-button"
              onClick={resetAll}
              disabled={isLoading}
            >
              重置
            </button>
          </div>
          
          {/* 可视化区域 */}
          <div className="visualization-area-encryption">
            <h2>可视化区域</h2>
            
            <div className="visualization-content">
              {/* 密钥可视化 */}
              <AnimatePresence>
                {currentKeys && (
                  <motion.div 
                    className="key-visualization-container"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.7 }}
                  >
                    <div className="key-pair">
                      {/* 公钥 */}
                      <motion.div 
                        className="public-key-box" 
                        initial={{ scale: 0.9 }}
                        animate={{ scale: 1 }}
                        transition={{ duration: 0.5, delay: 0.2 }}
                      >
                        <h3>公钥</h3>
                        <div className="key-details">
                          {Object.entries(currentKeys.publicKeyDetails || {}).map(([key, value], index) => (
                            <div className="key-detail" key={index}>
                              <span className="key-label">{key}:</span>
                              <span className="key-value">{typeof value === 'string' ? value : JSON.stringify(value)}</span>
                            </div>
                          ))}
                        </div>
                        <div className="key-icon public">
                          <span className="material-icon">🔓</span>
                        </div>
                      </motion.div>
                      
                      {/* 私钥 */}
                      <motion.div 
                        className="private-key-box"
                        initial={{ scale: 0.9 }}
                        animate={{ scale: 1 }}
                        transition={{ duration: 0.5, delay: 0.4 }}
                      >
                        <h3>私钥</h3>
                        <div className="key-details">
                          {Object.entries(currentKeys.privateKeyDetails || {}).map(([key, value], index) => (
                            <div className="key-detail" key={index}>
                              <span className="key-label">{key}:</span>
                              <span className="key-value">{typeof value === 'string' ? value : JSON.stringify(value)}</span>
                            </div>
                          ))}
                        </div>
                        <div className="key-icon private">
                          <span className="material-icon">🔐</span>
                        </div>
                      </motion.div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
              
              {/* 加密过程可视化 */}
              <AnimatePresence>
                {encryptionResult && (
                  <motion.div 
                    className="encryption-visualization"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.7, delay: 0.2 }}
                  >
                    <h3>加密过程</h3>
                    
                    <div className="encryption-flow">
                      {/* 明文消息 */}
                      <motion.div 
                        className="message-box"
                        initial={{ scale: 0.9 }}
                        animate={{ scale: 1 }}
                        transition={{ duration: 0.5 }}
                      >
                        <h4>明文消息</h4>
                        <div className="message-content">{truncateString(message)}</div>
                      </motion.div>
                      
                      {/* 箭头 */}
                      <motion.div 
                        className="flow-arrow"
                        initial={{ scaleX: 0 }}
                        animate={{ scaleX: 1 }}
                        transition={{ duration: 0.8, delay: 0.3 }}
                      />
                      
                      {/* 公钥符号 */}
                      <motion.div 
                        className="key-in-flow public"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.5, delay: 0.6 }}
                      >
                        <span className="key-symbol">🔓</span>
                      </motion.div>
                      
                      {/* 箭头 */}
                      <motion.div 
                        className="flow-arrow"
                        initial={{ scaleX: 0 }}
                        animate={{ scaleX: 1 }}
                        transition={{ duration: 0.8, delay: 0.9 }}
                      />
                      
                      {/* 密文 */}
                      <motion.div 
                        className="ciphertext-box"
                        initial={{ scale: 0.9, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        transition={{ duration: 0.5, delay: 1.2 }}
                      >
                        <h4>密文</h4>
                        <div className="ciphertext-content">
                          <div className="ciphertext-value">
                            {truncateString(encryptionResult.ciphertext, 60)}
                          </div>
                          
                          {encryptionResult.ephemeralKey && (
                            <div className="metadata-item">
                              <span className="metadata-label">临时密钥:</span>
                              <span className="metadata-value">{truncateString(encryptionResult.ephemeralKey, 30)}</span>
                            </div>
                          )}
                          
                          {encryptionResult.iv && (
                            <div className="metadata-item">
                              <span className="metadata-label">初始向量(IV):</span>
                              <span className="metadata-value">{encryptionResult.iv}</span>
                            </div>
                          )}
                          
                          {encryptionResult.metadata && (
                            <div className="additional-metadata">
                              <details>
                                <summary>更多元数据</summary>
                                <pre>{formatJSON(encryptionResult.metadata)}</pre>
                              </details>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
              
              {/* 解密过程可视化 */}
              <AnimatePresence>
                {decryptedMessage && (
                  <motion.div 
                    className="decryption-visualization"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.7, delay: 0.2 }}
                  >
                    <h3>解密过程</h3>
                    
                    <div className="decryption-flow">
                      {/* 密文 */}
                      <motion.div 
                        className="ciphertext-box"
                        initial={{ scale: 0.9 }}
                        animate={{ scale: 1 }}
                        transition={{ duration: 0.5 }}
                      >
                        <h4>密文</h4>
                        <div className="ciphertext-content">{truncateString(encryptionResult?.ciphertext || '', 60)}</div>
                      </motion.div>
                      
                      {/* 箭头 */}
                      <motion.div 
                        className="flow-arrow"
                        initial={{ scaleX: 0 }}
                        animate={{ scaleX: 1 }}
                        transition={{ duration: 0.8, delay: 0.3 }}
                      />
                      
                      {/* 私钥符号 */}
                      <motion.div 
                        className="key-in-flow private"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.5, delay: 0.6 }}
                      >
                        <span className="key-symbol">🔐</span>
                      </motion.div>
                      
                      {/* 箭头 */}
                      <motion.div 
                        className="flow-arrow"
                        initial={{ scaleX: 0 }}
                        animate={{ scaleX: 1 }}
                        transition={{ duration: 0.8, delay: 0.9 }}
                      />
                      
                      {/* 解密后的明文 */}
                      <motion.div 
                        className="plaintext-box"
                        initial={{ scale: 0.9, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        transition={{ duration: 0.5, delay: 1.2 }}
                      >
                        <h4>解密后的明文</h4>
                        <div className="plaintext-content">
                          {decryptedMessage}
                        </div>
                        {message === decryptedMessage ? (
                          <div className="verification-success">✓ 解密成功，与原始消息匹配</div>
                        ) : (
                          <div className="verification-failure">
                            ✗ 解密结果与原始消息不匹配
                            {encryptionResult?.metadata?.isSimulated && (
                              <div className="simulation-note">
                                (注意：这是使用模拟算法加密的结果，实际加密系统将保证正确性)
                              </div>
                            )}
                          </div>
                        )}
                      </motion.div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </div>
      </div>

      <style jsx>{`
        .encryption-page {
          padding: 0 1rem;
        }
        
        .algorithm-description {
          background: rgba(255, 255, 255, 0.8);
          padding: 1rem;
          border-radius: 8px;
          margin-bottom: 2rem;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
          font-size: 1rem;
          color: #444;
          line-height: 1.6;
        }
        
        .encryption-container {
          display: flex;
          gap: 2rem;
          margin-top: 2rem;
        }
        
        .control-panel {
          flex: 1;
          background: rgba(255, 255, 255, 0.9);
          padding: 1.5rem;
          border-radius: 10px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .visualization-area-encryption {
          flex: 2;
          background: rgba(255, 255, 255, 0.9);
          padding: 1.5rem;
          border-radius: 10px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
          min-height: 500px;
        }
        
        .control-group {
          margin-bottom: 1.5rem;
          padding-bottom: 1.5rem;
          border-bottom: 1px solid #eee;
        }
        
        h2 {
          margin-top: 0;
          margin-bottom: 1.5rem;
          color: #333;
          font-size: 1.5rem;
        }
        
        h3 {
          margin-top: 0;
          margin-bottom: 1rem;
          color: #555;
          font-size: 1.1rem;
        }
        
        textarea {
          width: 100%;
          padding: 0.8rem;
          border: 1px solid #ddd;
          border-radius: 8px;
          margin-bottom: 1rem;
          font-family: inherit;
          resize: vertical;
        }
        
        .action-button {
          padding: 0.8rem 1.5rem;
          background: #4a90e2;
          color: white;
          border: none;
          border-radius: 8px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .action-button:hover:not(:disabled) {
          background: #3a7bc8;
        }
        
        .action-button:disabled {
          background: #cccccc;
          cursor: not-allowed;
        }
        
        .reset-button {
          padding: 0.8rem 1.5rem;
          background: #e74c3c;
          color: white;
          border: none;
          border-radius: 8px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          margin-top: 1rem;
        }
        
        .reset-button:hover:not(:disabled) {
          background: #c0392b;
        }
        
        .reset-button:disabled {
          background: #cccccc;
          cursor: not-allowed;
        }
        
        .status-message {
          margin-top: 1rem;
          padding: 0.8rem;
          border-radius: 6px;
          text-align: center;
          font-weight: 500;
          animation: fadeIn 0.5s;
        }
        
        .status-message.keys-generated {
          background-color: #e3f2fd;
          color: #1565c0;
        }
        
        .status-message.message-encrypted {
          background-color: #e8f5e9;
          color: #2e7d32;
        }
        
        .status-message.message-decrypted {
          background-color: #fffde7;
          color: #f57f17;
        }
        
        .key-visualization-container {
          margin-bottom: 2rem;
        }
        
        .key-pair {
          display: flex;
          gap: 1.5rem;
          margin-bottom: 1.5rem;
        }
        
        .public-key-box,
        .private-key-box {
          flex: 1;
          padding: 1.2rem;
          border-radius: 8px;
          position: relative;
          overflow: hidden;
        }
        
        .public-key-box {
          background: #e3f2fd;
          border-left: 4px solid #2196f3;
        }
        
        .private-key-box {
          background: #ffebee;
          border-left: 4px solid #f44336;
        }
        
        .key-details {
          font-family: monospace;
          font-size: 0.9rem;
          background: rgba(255, 255, 255, 0.7);
          padding: 0.8rem;
          border-radius: 6px;
          margin-top: 1rem;
        }
        
        .key-detail {
          margin-bottom: 0.5rem;
          word-break: break-all;
        }
        
        .key-label {
          font-weight: bold;
          margin-right: 0.5rem;
        }
        
        .key-icon {
          position: absolute;
          top: 1rem;
          right: 1rem;
          width: 40px;
          height: 40px;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        
        .material-icon {
          font-size: 2rem;
        }
        
        .encryption-visualization,
        .decryption-visualization {
          margin-top: 2rem;
          padding-top: 1rem;
          border-top: 1px solid #eee;
        }
        
        .encryption-flow,
        .decryption-flow {
          display: flex;
          align-items: center;
          padding: 1rem 0;
        }
        
        .message-box,
        .ciphertext-box,
        .plaintext-box {
          padding: 1rem;
          border-radius: 8px;
          width: 220px;
        }
        
        .message-box {
          background: #e3f2fd;
          border-left: 4px solid #2196f3;
        }
        
        .ciphertext-box {
          background: #f3e5f5;
          border-left: 4px solid #9c27b0;
        }
        
        .plaintext-box {
          background: #e8f5e9;
          border-left: 4px solid #4caf50;
        }
        
        .message-content,
        .ciphertext-content,
        .plaintext-content {
          font-family: monospace;
          font-size: 0.9rem;
          background: rgba(255, 255, 255, 0.5);
          padding: 0.5rem;
          border-radius: 4px;
          margin-top: 0.5rem;
          word-break: break-all;
        }
        
        .flow-arrow {
          height: 3px;
          background: #555;
          width: 60px;
          position: relative;
          margin: 0 5px;
          transform-origin: left;
        }
        
        .flow-arrow::after {
          content: '';
          position: absolute;
          right: -8px;
          top: -5px;
          width: 0;
          height: 0;
          border-top: 6px solid transparent;
          border-bottom: 6px solid transparent;
          border-left: 8px solid #555;
        }
        
        .key-in-flow {
          width: 50px;
          height: 50px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0 10px;
        }
        
        .key-in-flow.public {
          background: #e3f2fd;
          box-shadow: 0 0 0 4px rgba(33, 150, 243, 0.3);
        }
        
        .key-in-flow.private {
          background: #ffebee;
          box-shadow: 0 0 0 4px rgba(244, 67, 54, 0.3);
        }
        
        .key-symbol {
          font-size: 1.8rem;
        }
        
        .metadata-item {
          margin-top: 0.5rem;
          font-size: 0.8rem;
        }
        
        .metadata-label {
          color: #555;
          font-weight: bold;
          margin-right: 0.5rem;
        }
        
        .additional-metadata {
          margin-top: 0.8rem;
          font-size: 0.8rem;
        }
        
        .additional-metadata summary {
          cursor: pointer;
          color: #2196f3;
        }
        
        .additional-metadata pre {
          margin-top: 0.5rem;
          background: rgba(255, 255, 255, 0.7);
          padding: 0.5rem;
          border-radius: 4px;
          overflow-x: auto;
        }
        
        .verification-success {
          margin-top: 0.8rem;
          color: #2e7d32;
          font-weight: 600;
        }
        
        .verification-failure {
          margin-top: 0.8rem;
          color: #c62828;
          font-weight: 600;
        }
        
        .simulation-note {
          margin-top: 0.8rem;
          color: #555;
          font-size: 0.8rem;
        }
        
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        
        @media (max-width: 1024px) {
          .encryption-container {
            flex-direction: column;
          }
          
          .key-pair {
            flex-direction: column;
          }
          
          .encryption-flow,
          .decryption-flow {
            flex-direction: column;
            gap: 1rem;
          }
          
          .flow-arrow {
            width: 3px;
            height: 40px;
            transform: rotate(90deg);
            margin: 10px 0;
          }
        }
      `}</style>
    </div>
  );
} 