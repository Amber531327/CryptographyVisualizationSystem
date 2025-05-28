import React, { useEffect, useRef } from 'react';

// 粒子接口定义
interface Particle {
  x: number;       // 粒子的x坐标
  y: number;       // 粒子的y坐标
  size: number;    // 粒子大小
  speedX: number;  // x方向速度
  speedY: number;  // y方向速度
  color: string;   // 粒子颜色
  opacity: number; // 透明度
}

// 粒子背景组件：创建动态粒子效果作为背景
const ParticleBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);      // Canvas元素引用
  const particles = useRef<Particle[]>([]);               // 粒子数组引用
  const animationFrameId = useRef<number>(0);             // 动画帧ID引用

  // 初始化画布和粒子
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // 设置画布大小为窗口大小
    const handleResize = () => {
      if (canvas) {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        // 窗口调整大小时重新初始化粒子
        initParticles();
      }
    };

    // 初始化粒子
    const initParticles = () => {
      particles.current = [];
      const numParticles = Math.floor((canvas.width * canvas.height) / 15000); // 根据屏幕大小调整粒子数量
      
      for (let i = 0; i < numParticles; i++) {
        particles.current.push({
          x: Math.random() * canvas.width,         // 随机x位置
          y: Math.random() * canvas.height,        // 随机y位置
          size: Math.random() * 3 + 1,             // 随机大小
          speedX: Math.random() * 0.5 - 0.25,      // 随机x速度
          speedY: Math.random() * 0.5 - 0.25,      // 随机y速度
          color: getRandomColor(),                 // 随机颜色
          opacity: Math.random() * 0.5 + 0.2       // 随机透明度
        });
      }
    };
    
    // 获取随机数字签名主题颜色
    const getRandomColor = () => {
      const colors = [
        'rgba(30, 144, 255, 0.5)', // 数字蓝
        'rgba(0, 128, 0, 0.5)',     // 安全绿
        'rgba(255, 165, 0, 0.5)',   // 密钥橙
        'rgba(138, 43, 226, 0.5)'   // 加密紫
      ];
      return colors[Math.floor(Math.random() * colors.length)];
    };

    // 动画函数
    const animate = () => {
      if (!canvas || !ctx) return;
      
      // 清除画布
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // 更新并绘制粒子
      particles.current.forEach(particle => {
        // 更新位置
        particle.x += particle.speedX;
        particle.y += particle.speedY;
        
        // 边缘环绕
        if (particle.x < 0) particle.x = canvas.width;
        if (particle.x > canvas.width) particle.x = 0;
        if (particle.y < 0) particle.y = canvas.height;
        if (particle.y > canvas.height) particle.y = 0;
        
        // 绘制粒子
        ctx.beginPath();
        ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
        ctx.fillStyle = particle.color;
        ctx.globalAlpha = particle.opacity;
        ctx.fill();
        ctx.globalAlpha = 1;
      });
      
      // 请求下一帧
      animationFrameId.current = requestAnimationFrame(animate);
    };

    // 初始化并开始动画
    handleResize();
    window.addEventListener('resize', handleResize);
    animate();

    // 清理函数
    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId.current);
    };
  }, []);

  return (
    <canvas 
      ref={canvasRef} 
      className="particle-background"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none', // 不捕获鼠标事件
        zIndex: -1              // 放在最底层
      }}
    />
  );
};

export default ParticleBackground; 