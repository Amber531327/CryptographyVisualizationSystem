import { useState, useEffect } from 'react';
import { EncryptionAlgorithmFactory } from '../algorithms/encryption-factory';
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
import { KeyPair, EncryptionResult } from '../algorithms/encryption-factory';
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
      text: '加密算法性能评估实验结果',
    },
  },
};

// 定义算法类型
type AlgorithmType = 'RSA' | 'ElGamal' | 'ECC';
type AlgorithmResults = Record<AlgorithmType, number[]>;
type AlgorithmAverages = Record<AlgorithmType, number>;
type AlgorithmKeys = Record<AlgorithmType, KeyPair>;
type AlgorithmEncryptionResults = Record<AlgorithmType, EncryptionResult>;

export default function EncryptionPerformance() {
  // 实验结果状态
  const [keyGenerationResults, setKeyGenerationResults] = useState<{
    times: AlgorithmResults;
    averages: AlgorithmAverages;
    isLoading: boolean;
  }>({
    times: { RSA: [], ElGamal: [], ECC: [] },
    averages: { RSA: 0, ElGamal: 0, ECC: 0 },
    isLoading: false,
  });

  const [encryptionResults, setEncryptionResults] = useState<{
    times: AlgorithmResults;
    averages: AlgorithmAverages;
    sizes: AlgorithmAverages;
    isLoading: boolean;
  }>({
    times: { RSA: [], ElGamal: [], ECC: [] },
    averages: { RSA: 0, ElGamal: 0, ECC: 0 },
    sizes: { RSA: 0, ElGamal: 0, ECC: 0 },
    isLoading: false,
  });

  const [decryptionResults, setDecryptionResults] = useState<{
    times: AlgorithmResults;
    averages: AlgorithmAverages;
    isLoading: boolean;
  }>({
    times: { RSA: [], ElGamal: [], ECC: [] },
    averages: { RSA: 0, ElGamal: 0, ECC: 0 },
    isLoading: false,
  });

  // 测试次数和测试消息
  const [testCount, setTestCount] = useState<number>(5);
  const [testMessage, setTestMessage] = useState<string>('这是一条用于加密性能测试的消息');
  
  // 存储生成的密钥，用于加密和解密测试
  const [generatedKeys, setGeneratedKeys] = useState<AlgorithmKeys | null>(null);
  
  // 存储生成的加密结果，用于解密测试
  const [generatedEncryptions, setGeneratedEncryptions] = useState<AlgorithmEncryptionResults | null>(null);

  // 实验1：密钥生成性能测试
  const runKeyGenerationTest = async () => {
    setKeyGenerationResults(prev => ({ ...prev, isLoading: true }));
    
    const algorithms: AlgorithmType[] = ['RSA', 'ElGamal', 'ECC'];
    const times: AlgorithmResults = { RSA: [], ElGamal: [], ECC: [] };
    const keys: AlgorithmKeys = { RSA: {} as KeyPair, ElGamal: {} as KeyPair, ECC: {} as KeyPair };
    
    for (const algo of algorithms) {
      const algorithm = EncryptionAlgorithmFactory.getAlgorithm(algo);
      
      for (let i = 0; i < testCount; i++) {
        const startTime = performance.now();
        const keyPair = await algorithm.generateKeys();
        const endTime = performance.now();
        
        times[algo].push(endTime - startTime);
        
        // 保存最后一次生成的密钥对，用于后续的加密和解密测试
        if (i === testCount - 1) {
          keys[algo] = keyPair;
        }
      }
    }
    
    // 计算平均值
    const averages: AlgorithmAverages = {
      RSA: times.RSA.reduce((sum, time) => sum + time, 0) / times.RSA.length,
      ElGamal: times.ElGamal.reduce((sum, time) => sum + time, 0) / times.ElGamal.length,
      ECC: times.ECC.reduce((sum, time) => sum + time, 0) / times.ECC.length,
    };
    
    setKeyGenerationResults({
      times,
      averages,
      isLoading: false,
    });
    
    setGeneratedKeys(keys);
  };
  
  // 实验2：加密性能测试
  const runEncryptionTest = async () => {
    if (!generatedKeys) {
      alert('请先运行密钥生成测试');
      return;
    }
    
    setEncryptionResults(prev => ({ ...prev, isLoading: true }));
    
    const algorithms: AlgorithmType[] = ['RSA', 'ElGamal', 'ECC'];
    const times: AlgorithmResults = { RSA: [], ElGamal: [], ECC: [] };
    const sizes: AlgorithmAverages = { RSA: 0, ElGamal: 0, ECC: 0 };
    const encryptResults: AlgorithmEncryptionResults = { 
      RSA: {} as EncryptionResult, 
      ElGamal: {} as EncryptionResult, 
      ECC: {} as EncryptionResult 
    };
    
    for (const algo of algorithms) {
      const algorithm = EncryptionAlgorithmFactory.getAlgorithm(algo);
      
      for (let i = 0; i < testCount; i++) {
        const startTime = performance.now();
        const encryptionResult = await algorithm.encrypt(testMessage, generatedKeys[algo].publicKey);
        const endTime = performance.now();
        
        times[algo].push(endTime - startTime);
        
        // 保存最后一次生成的加密结果，用于后续的解密测试
        if (i === testCount - 1) {
          encryptResults[algo] = encryptionResult;
          
          // 计算密文大小（字节数）
          const ciphertext = encryptionResult.ciphertext || '';
          const ephemeralKey = encryptionResult.ephemeralKey || '';
          const iv = encryptionResult.iv || '';
          
          // 计算所有相关数据的总大小
          const combinedData = ciphertext + ephemeralKey + iv;
          sizes[algo] = new TextEncoder().encode(combinedData).length;
        }
      }
    }
    
    // 计算平均值
    const averages: AlgorithmAverages = {
      RSA: times.RSA.reduce((sum, time) => sum + time, 0) / times.RSA.length,
      ElGamal: times.ElGamal.reduce((sum, time) => sum + time, 0) / times.ElGamal.length,
      ECC: times.ECC.reduce((sum, time) => sum + time, 0) / times.ECC.length,
    };
    
    setEncryptionResults({
      times,
      averages,
      sizes,
      isLoading: false,
    });
    
    setGeneratedEncryptions(encryptResults);
  };
  
  // 实验3：解密性能测试
  const runDecryptionTest = async () => {
    if (!generatedKeys || !generatedEncryptions) {
      alert('请先运行密钥生成和加密测试');
      return;
    }
    
    setDecryptionResults(prev => ({ ...prev, isLoading: true }));
    
    const algorithms: AlgorithmType[] = ['RSA', 'ElGamal', 'ECC'];
    const times: AlgorithmResults = { RSA: [], ElGamal: [], ECC: [] };
    
    for (const algo of algorithms) {
      const algorithm = EncryptionAlgorithmFactory.getAlgorithm(algo);
      
      for (let i = 0; i < testCount; i++) {
        const startTime = performance.now();
        await algorithm.decrypt(generatedEncryptions[algo], generatedKeys[algo].privateKey);
        const endTime = performance.now();
        
        times[algo].push(endTime - startTime);
      }
    }
    
    // 计算平均值
    const averages: AlgorithmAverages = {
      RSA: times.RSA.reduce((sum, time) => sum + time, 0) / times.RSA.length,
      ElGamal: times.ElGamal.reduce((sum, time) => sum + time, 0) / times.ElGamal.length,
      ECC: times.ECC.reduce((sum, time) => sum + time, 0) / times.ECC.length,
    };
    
    setDecryptionResults({
      times,
      averages,
      isLoading: false,
    });
  };

  // 图表数据准备
  const keyGenerationChartData = {
    labels: ['RSA', 'ElGamal', 'ECC'],
    datasets: [
      {
        label: '平均密钥生成时间 (ms)',
        data: [
          keyGenerationResults.averages.RSA,
          keyGenerationResults.averages.ElGamal,
          keyGenerationResults.averages.ECC
        ],
        backgroundColor: 'rgba(54, 162, 235, 0.6)',
      },
    ],
  };

  const encryptionChartData = {
    labels: ['RSA', 'ElGamal', 'ECC'],
    datasets: [
      {
        label: '平均加密时间 (ms)',
        data: [
          encryptionResults.averages.RSA,
          encryptionResults.averages.ElGamal,
          encryptionResults.averages.ECC
        ],
        backgroundColor: 'rgba(255, 99, 132, 0.6)',
      }
    ],
  };

  const ciphertextSizeChartData = {
    labels: ['RSA', 'ElGamal', 'ECC'],
    datasets: [
      {
        label: '密文大小 (bytes)',
        data: [
          encryptionResults.sizes.RSA,
          encryptionResults.sizes.ElGamal,
          encryptionResults.sizes.ECC
        ],
        backgroundColor: 'rgba(153, 102, 255, 0.6)',
      }
    ],
  };

  const decryptionChartData = {
    labels: ['RSA', 'ElGamal', 'ECC'],
    datasets: [
      {
        label: '平均解密时间 (ms)',
        data: [
          decryptionResults.averages.RSA,
          decryptionResults.averages.ElGamal,
          decryptionResults.averages.ECC
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
        公钥加密算法性能评估实验
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
                  <li><strong>ElGamal:</strong> {keyGenerationResults.averages.ElGamal.toFixed(2)} ms</li>
                  <li><strong>ECC:</strong> {keyGenerationResults.averages.ECC.toFixed(2)} ms</li>
                </ul>
              </div>
            </div>
          )}
        </div>

        {/* 实验2：加密性能测试 */}
        <div className="experiment-section">
          <h2>实验2：加密性能</h2>
          <button 
            onClick={runEncryptionTest}
            className="experiment-btn"
            disabled={encryptionResults.isLoading || !generatedKeys}
          >
            {encryptionResults.isLoading ? '测试中...' : '运行加密测试'}
          </button>

          {Object.values(encryptionResults.averages).some(v => v > 0) && (
            <>
              <div className="chart-container">
                <h3>平均加密时间 (ms)</h3>
                <Bar options={options} data={encryptionChartData} />
                <div className="result-details">
                  <h4>详细结果:</h4>
                  <ul>
                    <li><strong>RSA:</strong> {encryptionResults.averages.RSA.toFixed(2)} ms</li>
                    <li><strong>ElGamal:</strong> {encryptionResults.averages.ElGamal.toFixed(2)} ms</li>
                    <li><strong>ECC:</strong> {encryptionResults.averages.ECC.toFixed(2)} ms</li>
                  </ul>
                </div>
              </div>
              
              <div className="chart-container">
                <h3>密文大小 (bytes)</h3>
                <Bar options={options} data={ciphertextSizeChartData} />
                <div className="result-details">
                  <h4>详细结果:</h4>
                  <ul>
                    <li><strong>RSA:</strong> {encryptionResults.sizes.RSA} bytes</li>
                    <li><strong>ElGamal:</strong> {encryptionResults.sizes.ElGamal} bytes</li>
                    <li><strong>ECC:</strong> {encryptionResults.sizes.ECC} bytes</li>
                  </ul>
                </div>
              </div>
            </>
          )}
        </div>

        {/* 实验3：解密性能测试 */}
        <div className="experiment-section">
          <h2>实验3：解密性能</h2>
          <button 
            onClick={runDecryptionTest}
            className="experiment-btn"
            disabled={decryptionResults.isLoading || !generatedEncryptions}
          >
            {decryptionResults.isLoading ? '测试中...' : '运行解密测试'}
          </button>

          {Object.values(decryptionResults.averages).some(v => v > 0) && (
            <div className="chart-container">
              <h3>平均解密时间 (ms)</h3>
              <Bar options={options} data={decryptionChartData} />
              <div className="result-details">
                <h4>详细结果:</h4>
                <ul>
                  <li><strong>RSA:</strong> {decryptionResults.averages.RSA.toFixed(2)} ms</li>
                  <li><strong>ElGamal:</strong> {decryptionResults.averages.ElGamal.toFixed(2)} ms</li>
                  <li><strong>ECC:</strong> {decryptionResults.averages.ECC.toFixed(2)} ms</li>
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
          text-decoration: none;
          display: inline-block;
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