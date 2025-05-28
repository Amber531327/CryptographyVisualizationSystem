import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { AlgorithmFactory, KeyPair, SignatureResult } from '../algorithms';

// 浏览器专用库使用动态导入
let JSEncrypt: any = null;
let EC: any = null;

interface StepActionsProps {
  steps: string[];
  currentStep: number;
  onStepChange: (step: number) => void;
  algorithm: string;
  message: string;
  setMessage: (message: string) => void;
  setKeys: (keys: any) => void;
  keys: any;
  setSignature: (signature: any) => void;
  signature: any;
  setVerificationResult: (result: boolean | null) => void;
  setAnimation: (animation: string) => void;
  attackMode?: boolean;
  modifiedMessage?: string;
}

const StepActions: React.FC<StepActionsProps> = ({
  steps,
  currentStep,
  onStepChange,
  algorithm,
  message,
  setMessage,
  setKeys,
  keys,
  setSignature,
  signature,
  setVerificationResult,
  setAnimation,
  attackMode,
  modifiedMessage,
}) => {
  const [messageInput, setMessageInput] = useState('');
  const [isClient, setIsClient] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 组件挂载后加载浏览器环境专属的库
  useEffect(() => {
    import('jsencrypt').then(module => {
      JSEncrypt = module.default;
    });

    import('elliptic').then(module => {
      EC = module.ec;
    });

    // 判断是否处于客户端环境
    setIsClient(typeof window !== 'undefined');
  }, []);

  // 点击步骤按钮时触发的逻辑
  const handleStepClick = (step: number) => {
    if (step === 0) {
      // 第一步“输入消息”可随时访问
      onStepChange(step);
    } else if (step <= currentStep + 1 && (step === 1 || (step > 1 && message))) {
      // 其他步骤需要按照顺序进行，且需要先输入消息
      onStepChange(step);
    }
  };

  // 提交输入的消息
  const handleMessageSubmit = () => {
    if (messageInput.trim()) {
      setMessage(messageInput.trim());
      setAnimation('message-submitted');
      // 不自动跳转下一步，由用户手动点击
    }
  };

  // 生成密钥对
  const generateKeys = async () => {
    if (!isClient) return;

    try {
      setError(null);
      const cryptoAlgorithm = AlgorithmFactory.getAlgorithm(algorithm);
      const generatedKeys = await cryptoAlgorithm.generateKeys();

      setKeys(generatedKeys);
      setAnimation('keys-generated');
    } catch (err) {
      console.error(`生成${algorithm}密钥时出错:`, err);
      setError(`生成密钥时出错: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // 生成数字签名
  const generateSignature = async () => {
    if (!isClient || !keys) return;

    try {
      setError(null);
      const cryptoAlgorithm = AlgorithmFactory.getAlgorithm(algorithm);
      const generatedSignature = await cryptoAlgorithm.sign(message, keys);

      setSignature(generatedSignature);
      setAnimation('signature-generated');
    } catch (err) {
      console.error(`生成${algorithm}签名时出错:`, err);
      setError(`生成签名时出错: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // 验证数字签名
  const verifySignature = async () => {
    if (!isClient || !keys || !signature) return;

    try {
      setError(null);
      const cryptoAlgorithm = AlgorithmFactory.getAlgorithm(algorithm);

      // 模拟攻击模式下的验证逻辑
      if (attackMode) {
        if (modifiedMessage === message) {
          // 攻击修改后的消息与原始一致，则正常验证
          const result = await cryptoAlgorithm.verify(message, signature, keys);
          setVerificationResult(result);
          setAnimation(result ? 'verification-success' : 'verification-failure');
        } else {
          // 消息被篡改，验证应失败
          setVerificationResult(false);
          setAnimation('verification-failure');
        }
        return;
      }

      // 正常验证流程
      const result = await cryptoAlgorithm.verify(message, signature, keys);
      setVerificationResult(result);
      setAnimation(result ? 'verification-success' : 'verification-failure');
    } catch (err) {
      console.error(`验证${algorithm}签名时出错:`, err);
      setError(`验证签名时出错: ${err instanceof Error ? err.message : String(err)}`);
      setVerificationResult(false);
      setAnimation('verification-failure');
    }
  };

  // 根据当前步骤渲染对应内容
  const renderStepContent = () => {
    switch (currentStep) {
      case 0: // 输入消息
        return (
          <div className="step-content message-input">
            <textarea
              value={messageInput}
              onChange={(e) => setMessageInput(e.target.value)}
              placeholder="输入要签名的消息"
              rows={4}
            />
            <motion.button
              onClick={handleMessageSubmit}
              disabled={!messageInput.trim()}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="action-button"
            >
              提交消息
            </motion.button>
          </div>
        );
      case 1: // 生成密钥
        return (
          <div className="step-content key-generation">
            <motion.button
              onClick={generateKeys}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="action-button"
              disabled={!isClient}
            >
              生成 {algorithm} 密钥对
            </motion.button>
          </div>
        );
      case 2: // 生成签名
        return (
          <div className="step-content signature-generation">
            <motion.button
              onClick={generateSignature}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="action-button"
              disabled={!isClient || !keys}
            >
              生成数字签名
            </motion.button>
          </div>
        );
      case 3: // 验证签名
        return (
          <div className="step-content signature-verification">
            <motion.button
              onClick={verifySignature}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="action-button"
              disabled={!isClient || !keys || !signature}
            >
              验证数字签名
            </motion.button>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="step-actions">
      {/* 渲染步骤按钮 */}
      <div className="step-buttons">
        {steps.map((step, index) => (
          <motion.button
            key={index}
            className={`step-button ${currentStep === index ? 'active' : ''} ${
              index <= currentStep ? 'accessible' : 'locked'
            }`}
            onClick={() => handleStepClick(index)}
            whileHover={{ scale: index <= currentStep + 1 ? 1.05 : 1 }}
            whileTap={{ scale: index <= currentStep + 1 ? 0.95 : 1 }}
            disabled={index > currentStep + 1}
          >
            {step}
          </motion.button>
        ))}
      </div>

      {/* 显示错误信息 */}
      {error && <div className="error-message">{error}</div>}

      {/* 渲染当前步骤内容 */}
      {renderStepContent()}
    </div>
  );
};

// 简单模拟一个哈希函数（可视化使用）
const CryptoJS = {
  SHA256: (message: string) => {
    let hash = 0;
    for (let i = 0; i < message.length; i++) {
      hash = ((hash << 5) - hash) + message.charCodeAt(i);
      hash |= 0;
    }
    return hash.toString(16);
  }
};

export default StepActions;
