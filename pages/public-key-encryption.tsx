import { useState } from 'react';
import { motion } from 'framer-motion';
import ParticleBackground from '../components/ParticleBackground';
import Link from 'next/link';

export default function PublicKeyEncryptionPage() {
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
      
      <div className="main-content">
        <div className="empty-page-container">
          <motion.div 
            className="coming-soon"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <h2>功能开发中</h2>
            <p>公钥加密可视化系统正在开发中，敬请期待...</p>
            
            <motion.div 
              className="construction-icon"
              animate={{ 
                rotate: [0, 10, 0, -10, 0],
                y: [0, -5, 0, -5, 0]
              }}
              transition={{ 
                duration: 2.5,
                repeat: Infinity,
                repeatType: "loop"
              }}
            >
              🛠️
            </motion.div>
          </motion.div>
        </div>
      </div>
    </div>
  );
} 