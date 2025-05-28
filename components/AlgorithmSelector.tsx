import React from 'react';
import { motion } from 'framer-motion';

// 算法选择器组件的属性接口
interface AlgorithmSelectorProps {
  selectedAlgorithm: string;    // 当前选中的算法
  onSelectAlgorithm: (algorithm: string) => void;  // 选中算法时的回调函数
}

// 算法选择器组件：用于选择数字签名算法
const AlgorithmSelector: React.FC<AlgorithmSelectorProps> = ({
  selectedAlgorithm,
  onSelectAlgorithm,
}) => {
  // 支持的算法列表
  const algorithms = ['RSA', 'DSA', 'ECDSA'];

  return (
    <div className="algorithm-selector">
      {algorithms.map((algorithm) => (
        // 为每个算法创建一个动画按钮
        <motion.button
          key={algorithm}
          className={`algorithm-button ${selectedAlgorithm === algorithm ? 'selected' : ''}`}
          onClick={() => onSelectAlgorithm(algorithm)}
          whileHover={{ scale: 1.05 }}  // 悬停时缩放效果
          whileTap={{ scale: 0.95 }}    // 点击时缩放效果
        >
          {algorithm}
        </motion.button>
      ))}
    </div>
  );
};

export default AlgorithmSelector; 