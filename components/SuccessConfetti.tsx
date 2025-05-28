import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';

// 单个彩色碎片的接口定义
interface ConfettiPiece {
  id: number;                     // 碎片ID
  x: number;                      // 水平位置百分比
  delay: number;                  // 动画延迟时间
  duration: number;               // 动画持续时间
  color: string;                  // 碎片颜色
  size: number;                   // 碎片大小
  rotation: number;               // 旋转角度
  type: 'circle' | 'square' | 'triangle';  // 碎片形状
}

// 成功庆祝组件属性接口
interface SuccessConfettiProps {
  show: boolean;  // 是否显示彩色碎片效果
}

// 成功庆祝组件：显示彩色碎片庆祝效果
const SuccessConfetti: React.FC<SuccessConfettiProps> = ({ show }) => {
  const [confetti, setConfetti] = useState<ConfettiPiece[]>([]);
  
  useEffect(() => {
    if (show) {
      // 生成彩色碎片
      const pieces: ConfettiPiece[] = [];
      const colors = ['#4CAF50', '#8BC34A', '#CDDC39', '#FFEB3B', '#FFC107'];  // 绿色和黄色系列
      
      // 创建50个随机彩色碎片
      for (let i = 0; i < 50; i++) {
        pieces.push({
          id: i,
          x: Math.random() * 100,                     // 随机水平位置
          delay: Math.random() * 0.3,                 // 随机延迟
          duration: 1 + Math.random() * 2,            // 随机持续时间
          color: colors[Math.floor(Math.random() * colors.length)], // 随机颜色
          size: 5 + Math.random() * 10,               // 随机大小
          rotation: Math.random() * 360,              // 随机旋转角度
          type: ['circle', 'square', 'triangle'][Math.floor(Math.random() * 3)] as 'circle' | 'square' | 'triangle' // 随机形状
        });
      }
      
      setConfetti(pieces);
      
      // 动画完成后清除彩色碎片
      const timer = setTimeout(() => {
        setConfetti([]);
      }, 3000);  // 3秒后清除
      
      return () => clearTimeout(timer);  // 清理定时器
    }
  }, [show]);  // 当show属性变化时重新执行
  
  // 渲染单个彩色碎片
  const renderConfettiPiece = (piece: ConfettiPiece) => {
    switch (piece.type) {
      // 圆形碎片
      case 'circle':
        return (
          <motion.div
            key={piece.id}
            style={{
              position: 'absolute',
              left: `${piece.x}%`,
              top: '-5%',
              width: `${piece.size}px`,
              height: `${piece.size}px`,
              borderRadius: '50%',
              backgroundColor: piece.color,
              zIndex: 100
            }}
            initial={{ top: '-5%', rotate: 0 }}     // 初始位置和旋转
            animate={{ 
              top: '105%',                          // 移动到底部
              rotate: piece.rotation,               // 旋转到指定角度
              x: [0, Math.random() * 100 - 50, Math.random() * 100 - 50, Math.random() * 100 - 50],  // 水平摆动
              opacity: [1, 1, 0.8, 0]               // 逐渐消失
            }}
            transition={{ 
              duration: piece.duration, 
              delay: piece.delay, 
              ease: 'easeIn' 
            }}
          />
        );
      // 正方形碎片
      case 'square':
        return (
          <motion.div
            key={piece.id}
            style={{
              position: 'absolute',
              left: `${piece.x}%`,
              top: '-5%',
              width: `${piece.size}px`,
              height: `${piece.size}px`,
              backgroundColor: piece.color,
              zIndex: 100
            }}
            initial={{ top: '-5%', rotate: 0 }}
            animate={{ 
              top: '105%', 
              rotate: piece.rotation,
              x: [0, Math.random() * 100 - 50, Math.random() * 100 - 50, Math.random() * 100 - 50],
              opacity: [1, 1, 0.8, 0]
            }}
            transition={{ 
              duration: piece.duration, 
              delay: piece.delay, 
              ease: 'easeIn' 
            }}
          />
        );
      // 三角形碎片
      case 'triangle':
        return (
          <motion.div
            key={piece.id}
            style={{
              position: 'absolute',
              left: `${piece.x}%`,
              top: '-5%',
              width: 0,
              height: 0,
              borderLeft: `${piece.size/2}px solid transparent`,
              borderRight: `${piece.size/2}px solid transparent`,
              borderBottom: `${piece.size}px solid ${piece.color}`,
              zIndex: 100
            }}
            initial={{ top: '-5%', rotate: 0 }}
            animate={{ 
              top: '105%', 
              rotate: piece.rotation,
              x: [0, Math.random() * 100 - 50, Math.random() * 100 - 50, Math.random() * 100 - 50],
              opacity: [1, 1, 0.8, 0]
            }}
            transition={{ 
              duration: piece.duration, 
              delay: piece.delay, 
              ease: 'easeIn' 
            }}
          />
        );
      default:
        return null;
    }
  };
  
  // 如果不显示或没有碎片则不渲染
  if (!show || confetti.length === 0) return null;
  
  return (
    <div 
      style={{ 
        position: 'fixed', 
        top: 0, 
        left: 0, 
        width: '100%', 
        height: '100%', 
        pointerEvents: 'none',  // 不捕获鼠标事件
        overflow: 'hidden'      // 隐藏溢出部分
      }}
    >
      {confetti.map(piece => renderConfettiPiece(piece))}
    </div>
  );
};

export default SuccessConfetti; 