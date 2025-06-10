import { useState } from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import ParticleBackground from '../components/ParticleBackground';

export default function HomePage() {
  // 悬停状态
  const [hoveredCard, setHoveredCard] = useState<string | null>(null);

  return (
    <div className="home-container">
      {/* 粒子背景 */}
      <ParticleBackground />
      
      {/* 主标题区域 */}
      <motion.div 
        className="hero-section"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
      >
        <h1 className="main-title">密码学可视化系统</h1>
        <p className="subtitle">通过交互式演示了解数字签名和公钥加密的原理</p>
      </motion.div>
          
      {/* 系统介绍区域 */}
              <motion.div 
        className="intro-section"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
        transition={{ duration: 0.8, delay: 0.3 }}
                >
        <div className="intro-container">
          <h2 className="section-title">系统简介</h2>
          <p className="intro-text">
            本系统提供了密码学中两个核心概念的交互式可视化演示：数字签名与公钥加密。
            通过可视化的方式，您可以直观地理解这些加密技术的工作原理，以及它们如何保障信息安全。
          </p>
          
          <div className="security-features">
            <div className="feature">
              <div className="feature-icon">🔏</div>
              <h3>数据完整性</h3>
              <p>确保数据在传输过程中不被篡改</p>
                      </div>
            <div className="feature">
              <div className="feature-icon">🔒</div>
              <h3>数据保密性</h3>
              <p>保证敏感信息不被未授权方获取</p>
                    </div>
            <div className="feature">
              <div className="feature-icon">✓</div>
              <h3>身份认证</h3>
              <p>验证通信双方的真实身份</p>
                    </div>
                      </div>
                    </div>
                  </motion.div>
      
      {/* 功能导航卡片区域 */}
                  <motion.div 
        className="features-section"
        initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, delay: 0.5 }}
                  >
        <h2 className="section-title">功能模块</h2>
        
        <div className="feature-cards">
          {/* 数字签名卡片 */}
                <motion.div 
            className={`feature-card ${hoveredCard === 'signature' ? 'hovered' : ''}`}
            whileHover={{ 
              scale: 1.05,
              boxShadow: "0 10px 25px rgba(0, 0, 0, 0.2)"
            }}
            onHoverStart={() => setHoveredCard('signature')}
            onHoverEnd={() => setHoveredCard(null)}
          >
            <div className="card-content">
              <div className="card-icon">✍️</div>
              <h3 className="card-title">数字签名可视化</h3>
              <p className="card-description">
                通过交互式演示，了解数字签名的生成和验证过程，以及如何保障数据完整性与不可否认性。
                本模块支持RSA、DSA和ECDSA等多种签名算法。
              </p>
              
              <motion.div 
                className="card-overlay"
                initial={{ opacity: 0 }}
                animate={{ opacity: hoveredCard === 'signature' ? 1 : 0 }}
                transition={{ duration: 0.3 }}
              >
                <Link href="/digital-signature" className="card-button">
                  进入演示
                </Link>
              </motion.div>
            </div>
          </motion.div>
          
          {/* 公钥加密卡片 */}
          <motion.div 
            className={`feature-card ${hoveredCard === 'encryption' ? 'hovered' : ''}`}
            whileHover={{ 
              scale: 1.05,
              boxShadow: "0 10px 25px rgba(0, 0, 0, 0.2)"
            }}
            onHoverStart={() => setHoveredCard('encryption')}
            onHoverEnd={() => setHoveredCard(null)}
          >
            <div className="card-content">
              <div className="card-icon">🔐</div>
              <h3 className="card-title">公钥加密可视化</h3>
              <p className="card-description">
                探索公钥加密技术的工作原理，了解非对称加密如何保障数据安全及通信隐私，
                同时支持密文传输和密钥交换的可视化演示。
              </p>
              
              <motion.div 
                className="card-overlay"
                initial={{ opacity: 0 }}
                animate={{ opacity: hoveredCard === 'encryption' ? 1 : 0 }}
                transition={{ duration: 0.3 }}
              >
                <Link href="/public-key-encryption" className="card-button">
                  进入演示
                </Link>
              </motion.div>
                  </div>
                </motion.div>
                  </div>
                </motion.div>
                
      {/* 底部性能评估入口 */}
                <motion.div 
        className="performance-section"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
        transition={{ duration: 0.8, delay: 0.7 }}
                >
        <div className="performance-links">
          <Link href="/performance" className="performance-link">
            <div className="performance-card">
              <div className="performance-icon">📊</div>
              <div className="performance-text">
                <h3>数字签名性能评估</h3>
                <p>比较不同签名算法的性能指标</p>
              </div>
              <div className="arrow-icon">→</div>
                  </div>
          </Link>
          
          <Link href="/encryption-performance" className="performance-link">
            <div className="performance-card">
              <div className="performance-icon">📈</div>
              <div className="performance-text">
                <h3>公钥加密性能评估</h3>
                <p>比较不同加密算法的性能指标</p>
        </div>
              <div className="arrow-icon">→</div>
      </div>
        </Link>
      </div>
      </motion.div>

      {/* 页脚 */}
      <motion.footer 
        className="home-footer"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.8, delay: 0.9 }}
      >
        <p>密码学可视化教学系统 &copy; {new Date().getFullYear()}</p>
      </motion.footer>
    </div>
  );
} 