/**
 * 性能监控器
 * FPS 计算、内存监控、性能指标追踪
 */

export class PerformanceMonitor {
  constructor(options = {}) {
    this.frameCount = 0;
    this.fps = 0;
    this.deltaTime = 0;
    this.lastTime = performance.now();
    this.fpsUpdateInterval = options.fpsUpdateInterval || 500;
    this.lastFpsUpdate = this.lastTime;
    
    this.frameHistorySize = 60;
    this.frameHistory = [];
    
    this.stats = {
      trianglesRendered: 0,
      verticesRendered: 0,
      drawCalls: 0,
      textureBindings: 0,
      shaderSwitches: 0,
    };

    this.memoryStats = {
      jsHeapSize: 0,
      jsHeapLimit: 0,
      jsHeapUsage: 0,
    };

    this.enabled = options.enabled !== false;
    this.showFPS = options.showFPS || false;
  }

  /**
   * 更新帧计数
   */
  update() {
    const now = performance.now();
    this.deltaTime = (now - this.lastTime) / 1000; // 转换为秒
    this.lastTime = now;

    this.frameCount++;

    // 记录帧时间
    this.frameHistory.push(this.deltaTime);
    if (this.frameHistory.length > this.frameHistorySize) {
      this.frameHistory.shift();
    }

    // 更新 FPS
    if (now - this.lastFpsUpdate >= this.fpsUpdateInterval) {
      this.fps = Math.round(1000 / (this.fpsUpdateInterval / this.frameCount));
      this.frameCount = 0;
      this.lastFpsUpdate = now;

      // 更新内存统计
      this.updateMemoryStats();

      if (this.showFPS) {
        console.log(`FPS: ${this.fps}, 平均帧时间: ${this.getAverageFrameTime().toFixed(2)}ms`);
      }
    }
  }

  /**
   * 更新内存统计
   */
  updateMemoryStats() {
    if (performance.memory) {
      this.memoryStats.jsHeapSize = performance.memory.usedJSHeapSize / (1024 * 1024); // MB
      this.memoryStats.jsHeapLimit = performance.memory.jsHeapSizeLimit / (1024 * 1024);
      this.memoryStats.jsHeapUsage = (performance.memory.usedJSHeapSize / performance.memory.jsHeapSizeLimit) * 100;
    }
  }

  /**
   * 获取平均帧时间（毫秒）
   */
  getAverageFrameTime() {
    if (this.frameHistory.length === 0) return 0;
    const sum = this.frameHistory.reduce((a, b) => a + b, 0);
    return (sum / this.frameHistory.length) * 1000;
  }

  /**
   * 获取最大帧时间（毫秒）
   */
  getMaxFrameTime() {
    if (this.frameHistory.length === 0) return 0;
    return Math.max(...this.frameHistory) * 1000;
  }

  /**
   * 获取最小帧时间（毫秒）
   */
  getMinFrameTime() {
    if (this.frameHistory.length === 0) return 0;
    return Math.min(...this.frameHistory) * 1000;
  }

  /**
   * 获取帧时间方差
   */
  getFrameTimeVariance() {
    if (this.frameHistory.length === 0) return 0;
    const avg = this.getAverageFrameTime();
    const variance = this.frameHistory.reduce((sum, time) => {
      const diff = time * 1000 - avg;
      return sum + diff * diff;
    }, 0) / this.frameHistory.length;
    return Math.sqrt(variance);
  }

  /**
   * 重置统计数据
   */
  resetStats() {
    this.stats = {
      trianglesRendered: 0,
      verticesRendered: 0,
      drawCalls: 0,
      textureBindings: 0,
      shaderSwitches: 0,
    };
  }

  /**
   * 获取完整统计信息
   */
  getStats() {
    return {
      fps: this.fps,
      deltaTime: this.deltaTime,
      frameTime: this.getAverageFrameTime(),
      maxFrameTime: this.getMaxFrameTime(),
      minFrameTime: this.getMinFrameTime(),
      frameTimeVariance: this.getFrameTimeVariance(),
      memory: { ...this.memoryStats },
      rendering: { ...this.stats },
    };
  }

  /**
   * 获取性能等级 (基于 FPS)
   */
  getPerformanceLevel() {
    if (this.fps >= 100) return 'excellent'; // 优秀
    if (this.fps >= 60) return 'good';       // 良好
    if (this.fps >= 30) return 'fair';       // 一般
    return 'poor';                            // 差
  }

  /**
   * 应该降级性能吗？
   */
  shouldDegrade() {
    // 如果 FPS 低于 50 且波动大，考虑降级
    return this.fps < 50 && this.getFrameTimeVariance() > 5;
  }

  /**
   * 应该升级性能吗？
   */
  shouldUpgrade() {
    // 如果 FPS 高于 90 且稳定，考虑升级
    return this.fps > 90 && this.getFrameTimeVariance() < 2;
  }

  /**
   * 生成性能报告
   */
  generateReport() {
    const stats = this.getStats();
    const level = this.getPerformanceLevel();

    return `
========== 性能报告 ==========
FPS: ${stats.fps}
平均帧时间: ${stats.frameTime.toFixed(2)}ms
帧时间范围: ${stats.minFrameTime.toFixed(2)}ms - ${stats.maxFrameTime.toFixed(2)}ms
帧时间方差: ${stats.frameTimeVariance.toFixed(2)}ms
性能等级: ${level}

内存使用: ${stats.memory.jsHeapSize.toFixed(2)}MB / ${stats.memory.jsHeapLimit.toFixed(2)}MB (${stats.memory.jsHeapUsage.toFixed(1)}%)

渲染统计:
  - 绘制调用: ${stats.rendering.drawCalls}
  - 三角形: ${stats.rendering.trianglesRendered}
  - 顶点: ${stats.rendering.verticesRendered}
  - 纹理绑定: ${stats.rendering.textureBindings}
  - Shader 切换: ${stats.rendering.shaderSwitches}
==============================
    `;
  }

  /**
   * 销毁监控器
   */
  destroy() {
    this.frameHistory = [];
    this.stats = {};
    this.memoryStats = {};
  }
}

export default PerformanceMonitor;
