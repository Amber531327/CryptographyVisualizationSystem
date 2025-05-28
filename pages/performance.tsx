import { useState, useEffect } from 'react';
import { AlgorithmFactory } from '../algorithms';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import ParticleBackground from '../components/ParticleBackground';
import { KeyPair, SignatureResult } from '../algorithms';
import Link from 'next/link';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

// 图表选项
const options = {
  responsive: true,
  plugins: {
    legend: {
      position: 'top' as const,
    },
    title: {
      display: true,
      text: '性能评估实验结果',
    },
  },
};

// 定义算法类型
type AlgorithmType = 'RSA' | 'DSA' | 'ECDSA';
type AlgorithmResults = Record<AlgorithmType, number[]>;
type AlgorithmAverages = Record<AlgorithmType, number>;
type AlgorithmKeys = Record<AlgorithmType, KeyPair>;
type AlgorithmSignatures = Record<AlgorithmType, SignatureResult>;

export default function Performance() {
  // 实验结果状态
  const [keyGenerationResults, setKeyGenerationResults] = useState<{
    times: AlgorithmResults;
    averages: AlgorithmAverages;
    isLoading: boolean;
  }>({
    times: { RSA: [], DSA: [], ECDSA: [] },
    averages: { RSA: 0, DSA: 0, ECDSA: 0 },
    isLoading: false,
  });

  const [signatureResults, setSignatureResults] = useState<{
    times: AlgorithmResults;
    averages: AlgorithmAverages;
    sizes: AlgorithmAverages;
    isLoading: boolean;
  }>({
    times: { RSA: [], DSA: [], ECDSA: [] },
    averages: { RSA: 0, DSA: 0, ECDSA: 0 },
    sizes: { RSA: 0, DSA: 0, ECDSA: 0 },
    isLoading: false,
  });

  const [verificationResults, setVerificationResults] = useState<{
    times: AlgorithmResults;
    averages: AlgorithmAverages;
    isLoading: boolean;
  }>({
    times: { RSA: [], DSA: [], ECDSA: [] },
    averages: { RSA: 0, DSA: 0, ECDSA: 0 },
    isLoading: false,
  });

  // 测试次数和测试消息
  const [testCount, setTestCount] = useState<number>(5);
  const [testMessage, setTestMessage] = useState<string>('这是一条用于签名性能测试的消息');
  
  // 存储生成的密钥，用于签名和验证测试
  const [generatedKeys, setGeneratedKeys] = useState<AlgorithmKeys | null>(null);
  
  // 存储生成的签名，用于验证测试
  const [generatedSignatures, setGeneratedSignatures] = useState<AlgorithmSignatures | null>(null);

  // 实验1：密钥生成性能测试
  const runKeyGenerationTest = async () => {
    setKeyGenerationResults(prev => ({ ...prev, isLoading: true }));
    
    const algorithms: AlgorithmType[] = ['RSA', 'DSA', 'ECDSA'];
    const times: AlgorithmResults = { RSA: [], DSA: [], ECDSA: [] };
    const keys: AlgorithmKeys = { RSA: {} as KeyPair, DSA: {} as KeyPair, ECDSA: {} as KeyPair };
    
    for (const algo of algorithms) {
      const algorithm = AlgorithmFactory.getAlgorithm(algo);
      
      for (let i = 0; i < testCount; i++) {
        const startTime = performance.now();
        const keyPair = await algorithm.generateKeys();
        const endTime = performance.now();
        
        times[algo].push(endTime - startTime);
        
        // 保存最后一次生成的密钥对，用于后续的签名和验证测试
        if (i === testCount - 1) {
          keys[algo] = keyPair;
        }
      }
    }
    
    // 计算平均值
    const averages: AlgorithmAverages = {
      RSA: times.RSA.reduce((sum, time) => sum + time, 0) / times.RSA.length,
      DSA: times.DSA.reduce((sum, time) => sum + time, 0) / times.DSA.length,
      ECDSA: times.ECDSA.reduce((sum, time) => sum + time, 0) / times.ECDSA.length,
    };
    
    setKeyGenerationResults({
      times,
      averages,
      isLoading: false,
    });
    
    setGeneratedKeys(keys);
  };
  
  // 实验2：签名生成性能测试
  const runSignatureTest = async () => {
    if (!generatedKeys) {
      alert('请先运行密钥生成测试');
      return;
    }
    
    setSignatureResults(prev => ({ ...prev, isLoading: true }));
    
    const algorithms: AlgorithmType[] = ['RSA', 'DSA', 'ECDSA'];
    const times: AlgorithmResults = { RSA: [], DSA: [], ECDSA: [] };
    const sizes: AlgorithmAverages = { RSA: 0, DSA: 0, ECDSA: 0 };
    const signatures: AlgorithmSignatures = { 
      RSA: {} as SignatureResult, 
      DSA: {} as SignatureResult, 
      ECDSA: {} as SignatureResult 
    };
    
    for (const algo of algorithms) {
      const algorithm = AlgorithmFactory.getAlgorithm(algo);
      
      for (let i = 0; i < testCount; i++) {
        const startTime = performance.now();
        const signatureResult = await algorithm.sign(testMessage, generatedKeys[algo]);
        const endTime = performance.now();
        
        times[algo].push(endTime - startTime);
        
        // 保存最后一次生成的签名，用于后续的验证测试
        if (i === testCount - 1) {
          signatures[algo] = signatureResult;
          
          // 计算签名大小（字节数）
          if (algo === 'RSA' || algo === 'ECDSA') {
            // 对于RSA和ECDSA，计算signature字段的字节长度
            sizes[algo] = new TextEncoder().encode(
              typeof signatureResult.signature === 'string' 
                ? signatureResult.signature 
                : JSON.stringify(signatureResult.signature)
            ).length;
          } else if (algo === 'DSA') {
            // 对于DSA，计算r和s字段组合后的字节长度
            const r = signatureResult.r || '';
            const s = signatureResult.s || '';
            const combined = r + s;
            sizes[algo] = new TextEncoder().encode(combined).length;
          }
        }
      }
    }
    
    // 计算平均值
    const averages: AlgorithmAverages = {
      RSA: times.RSA.reduce((sum, time) => sum + time, 0) / times.RSA.length,
      DSA: times.DSA.reduce((sum, time) => sum + time, 0) / times.DSA.length,
      ECDSA: times.ECDSA.reduce((sum, time) => sum + time, 0) / times.ECDSA.length,
    };
    
    setSignatureResults({
      times,
      averages,
      sizes,
      isLoading: false,
    });
    
    setGeneratedSignatures(signatures);
  };
  
  // 实验3：签名验证性能测试
  const runVerificationTest = async () => {
    if (!generatedKeys || !generatedSignatures) {
      alert('请先运行密钥生成和签名测试');
      return;
    }
    
    setVerificationResults(prev => ({ ...prev, isLoading: true }));
    
    const algorithms: AlgorithmType[] = ['RSA', 'DSA', 'ECDSA'];
    const times: AlgorithmResults = { RSA: [], DSA: [], ECDSA: [] };
    
    for (const algo of algorithms) {
      const algorithm = AlgorithmFactory.getAlgorithm(algo);
      
      for (let i = 0; i < testCount; i++) {
        const startTime = performance.now();
        await algorithm.verify(testMessage, generatedSignatures[algo], generatedKeys[algo]);
        const endTime = performance.now();
        
        times[algo].push(endTime - startTime);
      }
    }
    
    // 计算平均值
    const averages: AlgorithmAverages = {
      RSA: times.RSA.reduce((sum, time) => sum + time, 0) / times.RSA.length,
      DSA: times.DSA.reduce((sum, time) => sum + time, 0) / times.DSA.length,
      ECDSA: times.ECDSA.reduce((sum, time) => sum + time, 0) / times.ECDSA.length,
    };
    
    setVerificationResults({
      times,
      averages,
      isLoading: false,
    });
  };

  // 图表数据准备
  const keyGenerationChartData = {
    labels: ['RSA', 'DSA', 'ECDSA'],
    datasets: [
      {
        label: '平均密钥生成时间 (ms)',
        data: [
          keyGenerationResults.averages.RSA,
          keyGenerationResults.averages.DSA,
          keyGenerationResults.averages.ECDSA
        ],
        backgroundColor: 'rgba(54, 162, 235, 0.6)',
      },
    ],
  };

  const signatureChartData = {
    labels: ['RSA', 'DSA', 'ECDSA'],
    datasets: [
      {
        label: '平均签名生成时间 (ms)',
        data: [
          signatureResults.averages.RSA,
          signatureResults.averages.DSA,
          signatureResults.averages.ECDSA
        ],
        backgroundColor: 'rgba(255, 99, 132, 0.6)',
      }
    ],
  };

  const signatureSizeChartData = {
    labels: ['RSA', 'DSA', 'ECDSA'],
    datasets: [
      {
        label: '签名大小 (bytes)',
        data: [
          signatureResults.sizes.RSA,
          signatureResults.sizes.DSA,
          signatureResults.sizes.ECDSA
        ],
        backgroundColor: 'rgba(153, 102, 255, 0.6)',
      }
    ],
  };

  const verificationChartData = {
    labels: ['RSA', 'DSA', 'ECDSA'],
    datasets: [
      {
        label: '平均签名验证时间 (ms)',
        data: [
          verificationResults.averages.RSA,
          verificationResults.averages.DSA,
          verificationResults.averages.ECDSA
        ],
        backgroundColor: 'rgba(255, 159, 64, 0.6)',
      }
    ],
  };

  return (
    <div className="container">
      {/* 添加粒子背景 */}
      <ParticleBackground />
      
      {/* 页面标题 */}
      <h1 className="title">
        数字签名性能评估实验
      </h1>
      
      {/* 返回主页按钮 */}
      <div className="back-to-home">
        <Link href="/" className="nav-button">
          返回首页
        </Link>
      </div>
      
      <div className="performance-settings">
        <div className="setting-group">
          <label>测试次数:</label>
          <input 
            type="number" 
            value={testCount} 
            onChange={e => setTestCount(Math.max(1, parseInt(e.target.value)))} 
            min="1"
          />
        </div>
        <div className="setting-group">
          <label>测试消息:</label>
          <input 
            type="text" 
            value={testMessage} 
            onChange={e => setTestMessage(e.target.value)} 
          />
        </div>
      </div>

      <div className="experiments">
        {/* 实验1：密钥生成性能测试 */}
        <div className="experiment-section">
          <h2>实验1：密钥生成性能</h2>
          <button 
            onClick={runKeyGenerationTest}
            className="experiment-btn"
            disabled={keyGenerationResults.isLoading}
          >
            {keyGenerationResults.isLoading ? '测试中...' : '运行密钥生成测试'}
          </button>

          {Object.values(keyGenerationResults.averages).some(v => v > 0) && (
            <div className="chart-container">
              <h3>平均密钥生成时间 (ms)</h3>
              <Bar options={options} data={keyGenerationChartData} />
              <div className="result-details">
                <h4>详细结果:</h4>
                <ul>
                  <li><strong>RSA:</strong> {keyGenerationResults.averages.RSA.toFixed(2)} ms</li>
                  <li><strong>DSA:</strong> {keyGenerationResults.averages.DSA.toFixed(2)} ms</li>
                  <li><strong>ECDSA:</strong> {keyGenerationResults.averages.ECDSA.toFixed(2)} ms</li>
                </ul>
              </div>
            </div>
          )}
        </div>

        {/* 实验2：签名生成性能测试 */}
        <div className="experiment-section">
          <h2>实验2：签名生成性能</h2>
          <button 
            onClick={runSignatureTest}
            className="experiment-btn"
            disabled={signatureResults.isLoading || !generatedKeys}
          >
            {signatureResults.isLoading ? '测试中...' : '运行签名生成测试'}
          </button>

          {Object.values(signatureResults.averages).some(v => v > 0) && (
            <>
              <div className="chart-container">
                <h3>平均签名生成时间 (ms)</h3>
                <Bar options={options} data={signatureChartData} />
                <div className="result-details">
                  <h4>详细结果:</h4>
                  <ul>
                    <li><strong>RSA:</strong> {signatureResults.averages.RSA.toFixed(2)} ms</li>
                    <li><strong>DSA:</strong> {signatureResults.averages.DSA.toFixed(2)} ms</li>
                    <li><strong>ECDSA:</strong> {signatureResults.averages.ECDSA.toFixed(2)} ms</li>
                  </ul>
                </div>
              </div>
              
              <div className="chart-container">
                <h3>签名大小 (bytes)</h3>
                <Bar options={options} data={signatureSizeChartData} />
                <div className="result-details">
                  <h4>详细结果:</h4>
                  <ul>
                    <li><strong>RSA:</strong> {signatureResults.sizes.RSA} bytes</li>
                    <li><strong>DSA:</strong> {signatureResults.sizes.DSA} bytes</li>
                    <li><strong>ECDSA:</strong> {signatureResults.sizes.ECDSA} bytes</li>
                  </ul>
                </div>
              </div>
            </>
          )}
        </div>

        {/* 实验3：签名验证性能测试 */}
        <div className="experiment-section">
          <h2>实验3：签名验证性能</h2>
          <button 
            onClick={runVerificationTest}
            className="experiment-btn"
            disabled={verificationResults.isLoading || !generatedSignatures}
          >
            {verificationResults.isLoading ? '测试中...' : '运行签名验证测试'}
          </button>

          {Object.values(verificationResults.averages).some(v => v > 0) && (
            <div className="chart-container">
              <h3>平均签名验证时间 (ms)</h3>
              <Bar options={options} data={verificationChartData} />
              <div className="result-details">
                <h4>详细结果:</h4>
                <ul>
                  <li><strong>RSA:</strong> {verificationResults.averages.RSA.toFixed(2)} ms</li>
                  <li><strong>DSA:</strong> {verificationResults.averages.DSA.toFixed(2)} ms</li>
                  <li><strong>ECDSA:</strong> {verificationResults.averages.ECDSA.toFixed(2)} ms</li>
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
      
      <style jsx>{`
        .container {
          min-height: 100vh;
          padding: 0 0.5rem;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          position: relative;
          z-index: 1;
        }

        .title {
          margin: 0;
          line-height: 1.15;
          font-size: 3rem;
          text-align: center;
          color: #0070f3;
          margin-bottom: 2rem;
          z-index: 1;
        }

        .performance-settings {
          display: flex;
          justify-content: center;
          margin-bottom: 2rem;
          gap: 2rem;
          width: 100%;
          max-width: 800px;
        }

        .setting-group {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .setting-group label {
          font-size: 1rem;
          font-weight: bold;
        }

        .setting-group input {
          padding: 0.5rem;
          border: 1px solid #ccc;
          border-radius: 4px;
        }

        .experiments {
          display: flex;
          flex-direction: column;
          width: 100%;
          max-width: 900px;
          gap: 2rem;
          margin-bottom: 3rem;
        }

        .experiment-section {
          background: rgba(255, 255, 255, 0.9);
          border-radius: 8px;
          padding: 1.5rem;
          box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .experiment-section h2 {
          margin-top: 0;
          color: #333;
          border-bottom: 2px solid #0070f3;
          padding-bottom: 0.5rem;
          margin-bottom: 1rem;
        }

        .experiment-btn {
          background-color: #0070f3;
          color: white;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 4px;
          font-size: 1rem;
          font-weight: bold;
          cursor: pointer;
          transition: background-color 0.3s;
          margin-bottom: 1rem;
        }

        .experiment-btn:hover {
          background-color: #0051a2;
        }

        .experiment-btn:disabled {
          background-color: #cccccc;
          cursor: not-allowed;
        }

        .chart-container {
          margin-top: 1.5rem;
          padding-top: 1rem;
          border-top: 1px solid #eaeaea;
        }

        .chart-container h3 {
          text-align: center;
          margin-bottom: 1rem;
          color: #333;
        }

        .result-details {
          margin-top: 1rem;
          background-color: #f7f7f7;
          padding: 1rem;
          border-radius: 4px;
        }

        .result-details h4 {
          margin-top: 0;
          margin-bottom: 0.5rem;
          color: #333;
        }

        .result-details ul {
          margin: 0;
          padding-left: 1.5rem;
        }

        .result-details li {
          margin-bottom: 0.25rem;
        }

        .back-to-home {
          position: absolute;
          top: 1rem;
          right: 1rem;
        }

        .nav-button {
          background-color: #0070f3;
          color: white;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 4px;
          font-size: 1rem;
          font-weight: bold;
          cursor: pointer;
          transition: background-color 0.3s;
        }

        .nav-button:hover {
          background-color: #0051a2;
        }

        @media (max-width: 768px) {
          .performance-settings {
            flex-direction: column;
            gap: 1rem;
          }
          
          .title {
            font-size: 2rem;
          }
        }
      `}</style>
    </div>
  );
} 