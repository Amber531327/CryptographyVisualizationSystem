import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import AlgorithmSelector from '../components/AlgorithmSelector';
import StepActions from '../components/StepActions';
import VisualizationArea from '../components/VisualizationArea';
import UserRole from '../components/UserRole';
import SuccessConfetti from '../components/SuccessConfetti';
import ParticleBackground from '../components/ParticleBackground';
import Link from 'next/link';


export default function DigitalSignaturePage() {
  // 选择的算法状态
  const [algorithm, setAlgorithm] = useState('RSA');
  // 当前步骤状态
  const [currentStep, setCurrentStep] = useState(0);
  // 消息状态
  const [message, setMessage] = useState('');
  // 密钥状态
  const [keys, setKeys] = useState<any>(null);
  // 签名状态
  const [signature, setSignature] = useState<any>(null);
  // 验证结果状态
  const [verificationResult, setVerificationResult] = useState<boolean | null>(null);
  // 动画状态
  const [animation, setAnimation] = useState<string | null>(null);
  // 攻击模式状态
  const [attackMode, setAttackMode] = useState(false);
  // 修改后的消息状态
  const [modifiedMessage, setModifiedMessage] = useState('');
  // 显示攻击输入框状态
  const [showAttackInput, setShowAttackInput] = useState(false);
  // 修改后消息的哈希值状态
  const [modifiedHash, setModifiedHash] = useState<string | null>(null);

  // 定义步骤名称数组
  const steps = ['输入消息', '密钥生成', '签名生成', '签名验证'];
  
  // 处理步骤变化的函数
  const handleStepChange = (step: number) => {
    if (step <= currentStep + 1) {
      setCurrentStep(step);
    }
  };

  // 截断消息以便显示的函数
  const getTruncatedMessage = () => {
    if (message.length > 10) {
      return `${message.substring(0, 10)}...`;
    }
    return message;
  };

  // 获取哈希显示值的函数
  const getHashDisplay = () => {
    if (signature && signature.messageHash) {
      return signature.messageHash.substring(0, 8) + '...';
    }
    return null;
  };

  // 获取修改后消息哈希显示值的函数
  const getModifiedHashDisplay = () => {
    if (modifiedHash) {
      return modifiedHash.substring(0, 8) + '...';
    }
    return null;
  };

  // 获取签名显示值的函数
  const getSignatureDisplay = () => {
    if (signature) {
      if (algorithm === 'RSA' && signature.signature) {
        return signature.signature.substring(0, 8) + '...';
      } else if (algorithm === 'DSA') {
        return `r: ${signature.r?.substring(0, 8)}..., s: ${signature.s?.substring(0, 8)}...`;
      } else if (algorithm === 'ECDSA' && signature.signature) {
        return signature.signature.substring(0, 8) + '...';
      }
    }
    return null;
  };

  // 处理开始攻击的函数
  const handleStartAttack = () => {
    // 开始攻击时清除现有的验证结果
    setVerificationResult(null);
    // 重置动画状态以移除任何验证指示器
    setAnimation(null);
    // 显示攻击输入框并设置攻击模式
    setShowAttackInput(true);
    setAttackMode(true);
  };

  // 处理提交修改后消息的函数
  const handleModifiedMessageSubmit = async () => {
    if (!modifiedMessage) return;
    
    // 重置验证结果以确保不显示验证指示器
    setVerificationResult(null);
    
    // 为修改后的消息生成哈希值
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(modifiedMessage);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      setModifiedHash(hashHex);
      setShowAttackInput(false);
      // 使用'attack-completed'作为动画名称，而非与验证相关的名称
      setAnimation('attack-completed');
    } catch (err) {
      console.error('Error generating hash:', err);
      // WebCrypto API失败时的简单哈希备用方案
      const hashHex = simpleHash(modifiedMessage);
      setModifiedHash(hashHex);
      setShowAttackInput(false);
      setAnimation('attack-completed');
    }
  };

  // 简单哈希函数（备用方案）
  const simpleHash = (text: string) => {
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, '0').repeat(8).substring(0, 64);
  };

  return (
    <div className="container">
      {/* 添加粒子背景 */}
      <ParticleBackground />
      
      {/* 页面标题 */}
      <h1 className="title">
        数字签名可视化系统
      </h1>
      
      {/* 返回主页按钮 */}
      <div className="back-to-home">
        <Link href="/" className="nav-button">
          返回首页
        </Link>
      </div>
      
      {/* 算法选择器组件 */}
      <AlgorithmSelector 
        selectedAlgorithm={algorithm} 
        onSelectAlgorithm={setAlgorithm} 
      />
      
      <div className="main-content">
        <div className="workflow">
          {/* 步骤操作组件 */}
          <StepActions 
            steps={steps}
            currentStep={currentStep} 
            onStepChange={handleStepChange} 
            algorithm={algorithm}
            message={message}
            setMessage={setMessage}
            setKeys={setKeys}
            keys={keys}
            setSignature={setSignature}
            signature={signature}
            setVerificationResult={setVerificationResult}
            setAnimation={setAnimation}
            attackMode={attackMode}
            modifiedMessage={modifiedMessage}
          />
          
          {/* 可视化区域组件 */}
          <VisualizationArea 
            currentStep={currentStep}
            algorithm={algorithm}
            message={message}
            keys={keys}
            signature={signature}
            verificationResult={verificationResult}
            animation={animation}
            attackMode={attackMode}
            modifiedMessage={modifiedMessage}
            attackedMessageHash={modifiedHash || undefined}
          />
        </div>
        
        <div className="user-roles">
          {/* 发送方和接收方用户角色 */}
          <UserRole type="sender" position="left" />
          <UserRole type="receiver" position="right" />
          
          {/* 消息流动可视化 */}
          <AnimatePresence>
            {message && (
              <motion.div 
                className="message-flow-container"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
              >
                <motion.div 
                  className="message-flow-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8 }}
                />
                <motion.div 
                  initial={{ scale: 0.8 }}
                  animate={{ scale: 1 }}
                  transition={{ duration: 0.5, delay: 0.3 }}
                >
                  <div className="message-icon">
                    <div className="message-paper">
                      ✉️
                    </div>
                  </div>
                </motion.div>
                <motion.div 
                  className="message-container"
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, delay: 0.6 }}
                >
                  <div className="message-content">
                    消息的内容：{getTruncatedMessage()}
                  </div>
                </motion.div>
              </motion.div>
            )}
          </AnimatePresence>
          
          {/* 哈希和签名流程可视化 */}
          <AnimatePresence>
            {currentStep >= 2 && signature && (
              <>
                {/* 哈希可视化 */}
                <motion.div 
                  className="hash-flow-container"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.3, delay: 0.2 }}
                >
                  <motion.div 
                    className="hash-flow-arrow"
                    initial={animation === 'signature-generated' ? { scaleX: 0 } : { scaleX: 1 }}
                    animate={{ scaleX: 1 }}
                    transition={{ duration: 0.8 }}
                  />
                  <motion.div 
                    initial={animation === 'signature-generated' ? { scale: 0.8 } : { scale: 1 }}
                    animate={{ scale: 1 }}
                    transition={{ duration: 0.5, delay: 0.3 }}
                  >
                    <div className="hash-icon">
                      <div className="hash-symbol">
                        #
                      </div>
                    </div>
                  </motion.div>
                  <motion.div 
                    className="hash-value-container"
                    initial={animation === 'signature-generated' ? { opacity: 0, y: -10 } : { opacity: 1, y: 0 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 0.6 }}
                  >
                    <div className="hash-value-content">
                      哈希后的值：{getHashDisplay()}
                    </div>
                  </motion.div>
                </motion.div>
                
                {/* 签名可视化 */}
                <motion.div 
                  className="signature-flow-container"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.3, delay: animation === 'signature-generated' ? 1.0 : 0.2 }}
                >
                  <motion.div 
                    className="signature-flow-arrow"
                    initial={animation === 'signature-generated' ? { scaleX: 0 } : { scaleX: 1 }}
                    animate={{ scaleX: 1 }}
                    transition={{ duration: 0.8 }}
                  />
                  <motion.div 
                    initial={animation === 'signature-generated' ? { scale: 0.8 } : { scale: 1 }}
                    animate={{ scale: 1 }}
                    transition={{ duration: 0.5, delay: 0.3 }}
                  >
                    <div className="signature-icon">
                      <div className="signature-symbol">
                        ✍️
                      </div>
                    </div>
                  </motion.div>
                  <motion.div 
                    className="signature-value-container"
                    initial={animation === 'signature-generated' ? { opacity: 0, y: -10 } : { opacity: 1, y: 0 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 0.6 }}
                  >
                    <div className="signature-value-content">
                      签名的值：{getSignatureDisplay()}
                    </div>
                  </motion.div>
                </motion.div>
              </>
            )}
          </AnimatePresence>
          
          {/* 验证流程可视化 */}
          <AnimatePresence>
            {currentStep === 3 && signature && (
              <>
                {/* 从接收方到签名图标的箭头 */}
                <motion.div 
                  className="receiver-to-signature-arrow"
                  initial={animation === 'verification-success' || animation === 'verification-failure' ? { scaleX: 0 } : { scaleX: 1 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8 }}
                />
                
                {/* 从签名向下的箭头 */}
                <motion.div 
                  className="signature-verification-arrow"
                  initial={animation === 'verification-success' || animation === 'verification-failure' ? { scaleY: 0 } : { scaleY: 1 }}
                  animate={{ scaleY: 1 }}
                  transition={{ duration: 0.8, delay: 0.3 }}
                />
                
                {/* 从公钥到签名验证过程的箭头 */}
                <motion.div 
                  className="pubkey-to-verification-arrow"
                  initial={animation === 'verification-success' || animation === 'verification-failure' ? { scaleX: 0 } : { scaleX: 1 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 0.6 }}
                />
                
                {/* 验证结果显示 */}
                {(animation === 'verification-success' || animation === 'verification-failure') && verificationResult !== null && (
                  <motion.div 
                    className="verification-result-container"
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 0.9 }}
                  >
                    <div className={`verification-result-content ${verificationResult ? 'success' : 'failure'}`}>
                      验证{verificationResult ? '成功' : '失败'}{verificationResult ? '✓' : '✗'}
                    </div>
                  </motion.div>
                )}

                {/* 验证成功时显示庆祝效果 */}
                <SuccessConfetti show={verificationResult === true && animation === 'verification-success'} />
                
               
              </>
            )}
          </AnimatePresence>
          
          {/* 攻击可视化 */}
          <AnimatePresence>
            {currentStep === 3 && (attackMode || verificationResult === true) && (
              <motion.div 
                className="attack-button-container"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
              >
                <div className="hacker-icon">
                  <img src="/images/hacker.jpg" alt="Hacker" className="hacker-image" />
                </div>
                {!attackMode && (
                  <motion.button
                    className="attack-button"
                    onClick={handleStartAttack}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    开始攻击
                  </motion.button>
                )}
              </motion.div>
            )}
          </AnimatePresence>
          
          {/* 攻击输入对话框 */}
          <AnimatePresence>
            {showAttackInput && (
              <motion.div 
                className="attack-input-container"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 20 }}
                transition={{ duration: 0.3 }}
              >
                <h3>篡改消息内容</h3>
                <textarea
                  value={modifiedMessage}
                  onChange={(e) => setModifiedMessage(e.target.value)}
                  placeholder="输入篡改后的消息内容"
                  rows={3}
                />
                <motion.button
                  className="attack-submit-button"
                  onClick={handleModifiedMessageSubmit}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  disabled={!modifiedMessage}
                >
                  提交篡改内容
                </motion.button>
              </motion.div>
            )}
          </AnimatePresence>
          
          {/* 攻击流程可视化 */}
          <AnimatePresence>
            {attackMode && modifiedHash && (
              <>
                {/* 从原始消息到黑客的箭头 */}
                <motion.div 
                  className="message-to-hacker-arrow"
                  initial={{ scaleY: 0 }}
                  animate={{ scaleY: 1 }}
                  transition={{ duration: 0.8 }}
                />
                
                {/* 黑客标签 - 不再显示黑客图标，因为上方已经有了 */}
                <motion.div 
                  className="hacker-flow-container"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.3, delay: 0.2 }}
                >
                  <div className="hacker-label">
                    开始攻击
                  </div>
                </motion.div>
                
                {/* 从黑客到修改后消息的箭头 */}
                <motion.div 
                  className="hacker-to-modified-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 0.4 }}
                />
                
                {/* 修改后的消息 */}
                <motion.div 
                  className="modified-message-container"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.3, delay: 0.6 }}
                >
                  <div className="modified-message-content">
                    篡改消息内容为 {modifiedMessage}
                  </div>
                </motion.div>
                
                {/* 从修改后消息到修改后哈希的箭头 */}
                <motion.div 
                  className="modified-to-hash-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 0.8 }}
                />
                
                {/* 修改后的哈希值 */}
                <motion.div 
                  className="modified-hash-container"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.3, delay: 1.0 }}
                >
                  <div className="modified-hash-content">
                    哈希后的值 {getModifiedHashDisplay()}
                  </div>
                </motion.div>
                
                {/* 从修改后哈希到验证的箭头 */}
                <motion.div 
                  className="modified-to-verification-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 1.2 }}
                />
                
                {/* 从哈希到验证失败的箭头 */}
                {verificationResult === false && (
                <motion.div 
                  className="hash-to-verification-failure-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 1.4 }}
                />
                )}
                
                {/* 从哈希到验证成功的箭头（当使用相同消息进行攻击时） */}
                {verificationResult === true && (
                <motion.div 
                  className="hash-to-verification-success-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 1.4 }}
                />
                )}
              </>
            )}
          </AnimatePresence>
        </div>
        
        <div className="keys-display-area"></div>
      </div>

      {/* 底部性能评估跳转按钮 */}
      <div className="performance-button-container">
        <Link href="/performance" className="performance-button">
          进入性能评估实验
        </Link>
      </div>

    </div>
  );
} 