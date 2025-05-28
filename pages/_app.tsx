import React from 'react';
import '../styles/globals.css';

// 应用组件属性接口定义
type AppProps = {
  Component: React.ComponentType<any>; // 页面组件
  pageProps: any; // 传递给页面组件的属性
};

// 应用根组件：负责渲染当前页面组件
function MyApp({ Component, pageProps }: AppProps) {
  return <Component {...pageProps} />;
}

export default MyApp; 