import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface VisualizationAreaProps {
  currentStep: number;
  algorithm: string;
  message: string;
  keys: any;
  signature: any;
  verificationResult: boolean | null;
  animation: string | null;
  attackMode?: boolean;
  modifiedMessage?: string;
  attackedMessageHash?: string;
}

const VisualizationArea: React.FC<VisualizationAreaProps> = ({
  currentStep,
  algorithm,
  message,
  keys,
  signature,
  verificationResult,
  animation,
  attackMode,
  modifiedMessage,
  attackedMessageHash,
}) => {
  // 展示目前步骤的组件
  const renderStepContent = () => {
    switch (currentStep) {
      case 0: // 消息输入
        return (
          <div className="visualization-content message-step">
            <h3>输入消息</h3>
            <p>请在左侧输入要签名的消息内容。</p>
            {message && (
              <div className="message-display">
                <h4>当前消息：</h4>
                <p className="message-text">{message}</p>
              </div>
            )}
          </div>
        );

      case 1: // 密钥生成
        return (
          <div className="visualization-content key-generation-step">
            <h3>{algorithm} 密钥生成</h3>
            <div className="key-visualization">
              {keys ? (
                <>
                  <motion.div
                    className="key public-key"
                    initial={{ x: -100, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    transition={{ duration: 0.5 }}
                  >
                    <h4>公钥</h4>
                    <div className="key-data">
                      {algorithm === 'RSA' && (
                        <>
                          <p className="key-snippet">
                            <strong>e (公钥指数):</strong> {keys.publicKey.e}
                          </p>
                          <p className="key-snippet">
                            <strong>n (模数):</strong> {keys.publicKey.n.substring(0, 20)}...
                          </p>
                          <p className="key-snippet key-size">
                            <strong>密钥大小:</strong> ≥2048位
                          </p>
                        </>
                      )}
                      {algorithm === 'DSA' && (
                        <p className="key-snippet">
                          y: {keys.publicKey.y.toString().substring(0, 15)}...
                        </p>
                      )}
                      {algorithm === 'ECDSA' && (
                        <p className="key-snippet">
                          x: {keys.publicKey.x?.substring(0, 15)}...<br/>
                          y: {keys.publicKey.y?.substring(0, 15)}...
                        </p>
                      )}
                    </div>
                  </motion.div>

                  <motion.div
                    className="key private-key"
                    initial={{ x: -100, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    transition={{ duration: 0.5, delay: 0.3 }}
                  >
                    <h4>私钥</h4>
                    <div className="key-data">
                      {algorithm === 'RSA' && (
                        <>
                          <p className="key-snippet">
                            <strong>d (私钥指数):</strong> {keys.privateKey.d.substring(0, 20)}...
                          </p>
                          <p className="key-snippet">
                            <strong>n (模数):</strong> {keys.privateKey.n.substring(0, 20)}...
                          </p>
                        </>
                      )}
                      {algorithm === 'DSA' && (
                        <p className="key-snippet">
                          x: {keys.privateKey.x.toString().substring(0, 15)}...
                        </p>
                      )}
                      {algorithm === 'ECDSA' && (
                        <p className="key-snippet">
                          d: {keys.privateKey.d?.substring(0, 15)}...
                        </p>
                      )}
                    </div>
                  </motion.div>

                  {animation === 'keys-generated' && (
                    <>
                      <motion.div
                        className="key-animation public-key-animation"
                        initial={{ scale: 1, x: 0, y: 0, opacity: 1 }}
                        animate={{
                          scale: 0.7,
                          x: 400,
                          y: 400,
                          opacity: 1,
                          transition: { duration: 1.5 },
                        }}
                        onAnimationComplete={() => {
                          // 动画完成后，将钥匙图标添加到keys-display-area
                          const keysArea = document.querySelector('.keys-display-area');
                          const publicKeyElement = document.createElement('div');
                          publicKeyElement.className = 'permanent-key public-key-permanent';
                          publicKeyElement.innerHTML = `
                            <div class="key-wrapper">
                              <img src="/images/key.jpg" alt="公钥" class="key-image" />
                              <div class="key-label public-key-label">公钥</div>
                            </div>
                          `;
                          keysArea?.appendChild(publicKeyElement);
                        }}
                      >
                        <div className="key-wrapper">
                          <img src="/images/key.jpg" alt="公钥" className="key-image" />
                          <div className="key-label public-key-label">公钥</div>
                        </div>
                      </motion.div>
                      
                      <motion.div
                        className="key-animation private-key-animation"
                        initial={{ scale: 1, x: 0, y: 0, opacity: 1 }}
                        animate={{
                          scale: 0.7,
                          x: -400,
                          y: 400,
                          opacity: 1,
                          transition: { duration: 1.5 },
                        }}
                        onAnimationComplete={() => {
                          // 动画完成后，将钥匙图标添加到keys-display-area
                          const keysArea = document.querySelector('.keys-display-area');
                          const privateKeyElement = document.createElement('div');
                          privateKeyElement.className = 'permanent-key private-key-permanent';
                          privateKeyElement.innerHTML = `
                            <div class="key-wrapper">
                              <img src="/images/key.jpg" alt="私钥" class="key-image" />
                              <div class="key-label private-key-label">私钥</div>
                            </div>
                          `;
                          keysArea?.appendChild(privateKeyElement);
                        }}
                      >
                        <div className="key-wrapper">
                          <img src="/images/key.jpg" alt="私钥" className="key-image" />
                          <div className="key-label private-key-label">私钥</div>
                        </div>
                      </motion.div>
                    </>
                  )}
                </>
              ) : (
                <p>点击左侧按钮生成 {algorithm} 密钥对。</p>
              )}
            </div>
          </div>
        );

      case 2: // 签名生成
        return (
          <div className="visualization-content signature-generation-step">
            <h3>{algorithm} 签名生成</h3>
            <div className="signature-visualization">
              <div className="sig-process">
                <div className="sig-item message-box">
                  <h4>消息</h4>
                  <p>{message}</p>
                </div>
                <motion.div
                  className="sig-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.5 }}
                ></motion.div>
                <div className="sig-item hash-box">
                  <h4>SHA-256 哈希</h4>
                  {signature && algorithm === 'RSA' && signature.messageHash && (
                    <p className="hash-value">{signature.messageHash.substring(0, 20)}...</p>
                  )}
                  {(!signature || algorithm !== 'RSA' || !signature.messageHash) && (
                    <p>对消息进行哈希</p>
                  )}
                </div>
                <motion.div
                  className="sig-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.5, delay: 0.3 }}
                ></motion.div>
                <div className="sig-item private-key-box">
                  <h4>私钥签名</h4>
                  {algorithm === 'RSA' && (
                    <>
                      <p className="formula">s = H(m)^d mod n</p>
                      <div className="padding-info">使用PSS填充</div>
                      {signature && signature.salt && (
                        <div className="salt-info">
                          <span>盐值: </span>
                          <code>{signature.salt.substring(0, 16)}...</code>
                        </div>
                      )}
                    </>
                  )}
                  {algorithm !== 'RSA' && (
                    <p>{algorithm}</p>
                  )}
                </div>
                <motion.div
                  className="sig-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.5, delay: 0.6 }}
                ></motion.div>
                <div className="sig-item signature-box">
                  <h4>签名值</h4>
                  {signature && (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ duration: 0.5 }}
                      className="signature-value"
                    >
                      {algorithm === 'RSA' && (
                        <p>s = {signature.signature.substring(0, 20)}...</p>
                      )}
                      {algorithm === 'DSA' && (
                        <p>
                          r: {signature.r.substring(0, 10)}...<br />
                          s: {signature.s.substring(0, 10)}...
                        </p>
                      )}
                      {algorithm === 'ECDSA' && (
                        <p>{signature.signature.substring(0, 20)}...</p>
                      )}
                    </motion.div>
                  )}
                </div>
              </div>
            </div>
          </div>
        );

      case 3: // 签名验证
        return (
          <div className="visualization-content signature-verification-step">
            <h3>{algorithm} 签名验证</h3>
            <div className="verification-visualization">
              <div className="verify-process">
                <div className="verify-group">
                  <div className="verify-item message-box">
                    <h4>消息</h4>
                    <p>{attackMode ? modifiedMessage : message}</p>
                    {algorithm === 'RSA' && signature && signature.messageHash && !attackMode && (
                      <p className="hash-value">
                        <strong>SHA-256:</strong> {signature.messageHash.substring(0, 15)}...
                      </p>
                    )}
                    {attackMode && (
                      <>
                        <p className="hash-value">
                          <strong>SHA-256:</strong> {attackedMessageHash ? attackedMessageHash.substring(0, 15) : "..."}...
                        </p>
                        {modifiedMessage !== message && (
                        <div className="attacked-message-indicator">
                          <span>⚠️ 消息已被篡改</span>
                        </div>
                        )}
                      </>
                    )}
                  </div>
                  <div className="verify-item signature-box">
                    <h4>签名值</h4>
                    {algorithm === 'RSA' && signature && (
                      <>
                        <p>s = {signature.signature.substring(0, 15)}...</p>
                        {signature.salt && (
                          <div className="salt-info small">
                            <span>PSS盐值: </span>
                            <code>{signature.salt.substring(0, 12)}...</code>
                          </div>
                        )}
                      </>
                    )}
                    {algorithm === 'DSA' && signature && (
                      <p>
                        r: {signature.r.substring(0, 8)}...<br />
                        s: {signature.s.substring(0, 8)}...
                      </p>
                    )}
                    {algorithm === 'ECDSA' && signature && (
                      <p>{signature.signature.substring(0, 15)}...</p>
                    )}
                    {attackMode && (
                      <div className="original-signature-indicator">
                        <span>原始消息的签名</span>
                      </div>
                    )}
                  </div>
                </div>
                <motion.div
                  className="verify-arrow"
                  initial={{ scaleY: 0 }}
                  animate={{ scaleY: verificationResult !== null ? 1 : 0 }}
                  transition={{ duration: 0.5 }}
                ></motion.div>
                <div className="verify-item public-key-box">
                  <h4>公钥验证</h4>
                  {algorithm === 'RSA' && (
                    <>
                      <p className="formula">验证: H(m) == s^e mod n</p>
                      <div className="padding-info">使用PSS填充</div>
                    </>
                  )}
                  {algorithm !== 'RSA' && (
                    <p>{algorithm}</p>
                  )}
                </div>
                <motion.div
                  className="verify-arrow"
                  initial={{ scaleY: 0 }}
                  animate={{ scaleY: verificationResult !== null ? 1 : 0 }}
                  transition={{ duration: 0.5, delay: 0.3 }}
                ></motion.div>
                <div className="verify-result">
                  <h4>验证结果</h4>
                  <AnimatePresence>
                    {verificationResult !== null && (
                      <motion.div
                        className={`result-indicator ${!verificationResult ? 'failure' : 'success'}`}
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        exit={{ scale: 0 }}
                        transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                      >
                        {!verificationResult ? (
                          <span>验证失败 ✗</span>
                        ) : (
                          <span>验证成功 ✓</span>
                        )}
                      </motion.div>
                    )}
                    {attackMode && verificationResult !== null && !verificationResult && (
                      <motion.div
                        className="attack-explanation"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.5, delay: 0.3 }}
                      >
                        <p>签名无法验证，因为消息已被篡改，哈希值不匹配！</p>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>
            </div>
          </div>
        );

      default:
        return <div>选择步骤开始</div>;
    }
  };

  return (
    <div className="visualization-area">
      {renderStepContent()}
    </div>
  );
};

export default VisualizationArea; 