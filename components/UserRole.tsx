import React from 'react';
import { motion } from 'framer-motion';

// 用户角色属性接口定义
interface UserRoleProps {
  type: 'sender' | 'receiver'; // 用户类型：发送方或接收方
  position?: 'left' | 'right'; // 位置：左侧或右侧（可选参数）
}

// UserRole组件：显示发送方或接收方的用户角色
const UserRole: React.FC<UserRoleProps> = ({ type, position = type === 'sender' ? 'left' : 'right' }) => {
  return (
    <div className={`user-role ${type} ${position}`}>
      {/* 用户头像，带有动画效果 */}
      <motion.div
        className="avatar"
        initial={{ scale: 0.8 }} // 初始缩放比例
        animate={{ scale: 1 }} // 动画目标缩放比例
        transition={{ duration: 0.3 }} // 动画持续时间
      >
        <img src="/images/person.png" alt={type === 'sender' ? '发送方' : '接收方'} className="avatar-image" />
      </motion.div>
      {/* 用户角色标签 */}
      <p className="role-label">
        {type === 'sender' ? '发送方' : '接收方'}
      </p>
    </div>
  );
};

export default UserRole; 