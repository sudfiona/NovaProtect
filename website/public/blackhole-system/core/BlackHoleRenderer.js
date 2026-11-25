/**
 * 黑洞渲染器 - 主控制器
 * 管理整个渲染管道和系统流程
 */

import { DEFAULT_CONFIG, QUALITY_PRESETS, mergeConfig } from '../config/config.js';
import { WebGLManager } from './WebGLManager.js';
import { ShaderProgram } from './ShaderProgram.js';
import { PerformanceMonitor } from './PerformanceMonitor.js';
import { ParticleSystem } from '../particles/ParticleSystem.js';
import { InteractionManager } from '../interaction/InteractionManager.js';
import {
  BLACKHOLE_VERTEX_SHADER,
  BLACKHOLE_FRAGMENT_SHADER,
  PARTICLE_VERTEX_SHADER,
  PARTICLE_FRAGMENT_SHADER,
} from '../shaders/shaders.js';

export class BlackHoleRenderer {
  constructor(options = {}) {
    this.canvas = options.canvas || this.createCanvas();
    this.isRunning = false;
    this.animationFrameId = null;
    this.lastFrameTime = Date.now();

    // 合并配置
    this.config = this.initConfig(options);

    // 初始化各个系统
    this.webGLManager = new WebGLManager(this.canvas, { debug: this.config.debug.enabled });
    this.gl = this.webGLManager.gl;

    this.performanceMonitor = new PerformanceMonitor(this.config.performance);
    this.particleSystem = new ParticleSystem(this.gl, this.config.particles.defaultCount);
    this.interactionManager = new InteractionManager(this.canvas, this.config.interaction);

    // 初始化 Shader
    this.initShaders();

    // 初始化几何体
    this.initGeometry();

    // 设置视口
    this.handleResize();
    window.addEventListener('resize', this.handleResize.bind(this));

    console.log('[BlackHole] 渲染器初始化完成');
  }

  /**
   * 初始化配置
   */
  initConfig(options) {
    let config = { ...DEFAULT_CONFIG };

    // 应用质量预设
    if (options.quality && options.quality !== 'auto') {
      const preset = QUALITY_PRESETS[options.quality];
      if (preset) {
        config = mergeConfig(config, preset);
      }
    }

    // 合并用户配置
    if (options.config) {
      config = mergeConfig(config, options.config);
    }

    // 自动检测质量
    if (options.quality === 'auto' || options.quality === undefined) {
      this.autoDetectQuality(config);
    }

    return config;
  }

  /**
   * 自动检测设备质量
   */
  autoDetectQuality(config) {
    const canvas = this.canvas;
    const width = window.innerWidth;
    const height = window.innerHeight;

    // 计算分辨率
    const resolution = width * height;
    const is4K = resolution >= 3840 * 2160;
    const is1440p = resolution >= 2560 * 1440;
    const is1080p = resolution >= 1920 * 1080;
    const isMobile = width <= 768;

    // 检测性能
    const hardwareConcurrency = navigator.hardwareConcurrency || 4;
    const deviceMemory = navigator.deviceMemory || 4;

    let quality = 'medium';

    if (isMobile) {
      quality = deviceMemory <= 4 ? 'mobile' : 'low';
    } else if (is4K) {
      quality = 'high';
    } else if (is1440p) {
      quality = 'high';
    } else if (is1080p) {
      quality = hardwareConcurrency >= 4 ? 'medium' : 'low';
    }

    console.log(`[BlackHole] 自动检测质量: ${quality} (分辨率: ${width}x${height}, 内存: ${deviceMemory}GB, CPU: ${hardwareConcurrency}核)`);

    const preset = QUALITY_PRESETS[quality];
    if (preset) {
      Object.assign(config, preset);
    }
  }

  /**
   * 初始化 Shader
   */
  initShaders() {
    this.blackholeProgram = new ShaderProgram(
      this.gl,
      BLACKHOLE_VERTEX_SHADER,
      BLACKHOLE_FRAGMENT_SHADER,
      'blackhole'
    );

    this.particleProgram = new ShaderProgram(
      this.gl,
      PARTICLE_VERTEX_SHADER,
      PARTICLE_FRAGMENT_SHADER,
      'particle'
    );
  }

  /**
   * 初始化几何体
   */
  initGeometry() {
    // 球体（黑洞体积）
    this.blackholeMesh = this.createUVSphere(2, 32, 32);

    // 吸积盘
    this.diskMesh = this.createDisk(3, 5, 32);

    // 天空盒
    this.skyboxMesh = this.createUVSphere(100, 16, 16);
  }

  /**
   * 创建 UV 球体
   */
  createUVSphere(radius, widthSegments, heightSegments) {
    const vertices = [];
    const indices = [];

    for (let y = 0; y <= heightSegments; y++) {
      const theta = (y / heightSegments) * Math.PI;
      const sinTheta = Math.sin(theta);
      const cosTheta = Math.cos(theta);

      for (let x = 0; x <= widthSegments; x++) {
        const phi = (x / widthSegments) * Math.PI * 2;
        const sinPhi = Math.sin(phi);
        const cosPhi = Math.cos(phi);

        const vx = cosPhi * sinTheta * radius;
        const vy = cosTheta * radius;
        const vz = sinPhi * sinTheta * radius;

        vertices.push(vx, vy, vz);
      }
    }

    for (let y = 0; y < heightSegments; y++) {
      for (let x = 0; x < widthSegments; x++) {
        const a = y * (widthSegments + 1) + x;
        const b = a + widthSegments + 1;

        indices.push(a, b, a + 1);
        indices.push(b, b + 1, a + 1);
      }
    }

    return {
      vertices: new Float32Array(vertices),
      indices: new Uint32Array(indices),
      vertexCount: indices.length,
    };
  }

  /**
   * 创建吸积盘
   */
  createDisk(innerRadius, outerRadius, segments) {
    const vertices = [];
    const indices = [];

    for (let i = 0; i <= segments; i++) {
      const angle = (i / segments) * Math.PI * 2;
      const cos = Math.cos(angle);
      const sin = Math.sin(angle);

      vertices.push(innerRadius * cos, 0, innerRadius * sin);
      vertices.push(outerRadius * cos, 0, outerRadius * sin);
    }

    for (let i = 0; i < segments; i++) {
      const a = i * 2;
      const b = a + 1;
      const c = (i + 1) * 2;
      const d = c + 1;

      indices.push(a, b, c);
      indices.push(b, d, c);
    }

    return {
      vertices: new Float32Array(vertices),
      indices: new Uint32Array(indices),
      vertexCount: indices.length,
    };
  }

  /**
   * 创建四边形
   */
  createQuad() {
    const vertices = [
      -1, -1, 0,
       1, -1, 0,
      -1,  1, 0,
       1,  1, 0,
    ];

    const indices = [0, 1, 2, 1, 3, 2];

    return {
      vertices: new Float32Array(vertices),
      indices: new Uint32Array(indices),
      vertexCount: indices.length,
    };
  }

  /**
   * 处理窗口大小改变
   */
  handleResize() {
    const dpr = window.devicePixelRatio || 1;
    const width = window.innerWidth;
    const height = window.innerHeight;

    this.canvas.width = width * dpr;
    this.canvas.height = height * dpr;
    this.canvas.style.width = width + 'px';
    this.canvas.style.height = height + 'px';

    this.webGLManager.setViewport(0, 0, this.canvas.width, this.canvas.height);

    // 更新投影矩阵
    this.updateProjectionMatrix();
  }

  /**
   * 更新投影矩阵
   */
  updateProjectionMatrix() {
    const fov = this.config.camera.fov * Math.PI / 180;
    const aspect = this.canvas.width / this.canvas.height;
    const near = this.config.camera.near;
    const far = this.config.camera.far;

    // 计算投影矩阵（透视投影）
    const f = 1 / Math.tan(fov / 2);
    this.projectionMatrix = new Float32Array([
      f / aspect, 0, 0, 0,
      0, f, 0, 0,
      0, 0, (far + near) / (near - far), -1,
      0, 0, (2 * far * near) / (near - far), 0,
    ]);
  }

  /**
   * 渲染单帧
   */
  render() {
    // 更新性能监控
    this.performanceMonitor.update();

    // 计算 deltaTime
    const now = Date.now();
    const deltaTime = (now - this.lastFrameTime) / 1000;
    this.lastFrameTime = now;

    // 更新交互
    this.interactionManager.update(deltaTime);

    // 更新粒子系统
    this.particleSystem.attractionPoint = this.config.blackhole.position || [0, 0, 0];
    this.particleSystem.attractionStrength = this.config.blackhole.mass * 0.001;
    this.particleSystem.update(deltaTime);

    // 发射粒子
    if (Math.random() < 0.5) {
      this.particleSystem.emit({
        position: [0, 0, 0],
        velocity: [0, 0, 0],
        count: Math.floor(this.config.particles.emissionRate * deltaTime),
        speedRange: this.config.particles.speedRange,
        sizeRange: this.config.particles.sizeRange,
        colorPalette: this.config.particles.colorPalette,
        lifespan: this.config.particles.lifespan,
      });
    }

    // 清空画布
    this.webGLManager.clear(0, 0, 0, 1);

    // 渲染粒子
    this.particleSystem.render(this.particleProgram);

    // 检查是否应该降级性能
    if (this.config.performance.adaptiveFrameRate) {
      if (this.performanceMonitor.shouldDegrade()) {
        this.degradePerformance();
      } else if (this.performanceMonitor.shouldUpgrade()) {
        this.upgradePerformance();
      }
    }

    // 请求下一帧
    if (this.isRunning) {
      this.animationFrameId = requestAnimationFrame(() => this.render());
    }
  }

  /**
   * 降级性能
   */
  degradePerformance() {
    console.warn('[BlackHole] 性能降级触发');
    // 实现性能降级逻辑
    this.config.particles.defaultCount = Math.max(
      this.config.particles.defaultCount * 0.75,
      5000
    );
  }

  /**
   * 升级性能
   */
  upgradePerformance() {
    console.log('[BlackHole] 性能升级触发');
    // 实现性能升级逻辑
    this.config.particles.defaultCount = Math.min(
      this.config.particles.defaultCount * 1.1,
      100000
    );
  }

  /**
   * 启动渲染
   */
  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    console.log('[BlackHole] 渲染启动');
    this.render();
  }

  /**
   * 停止渲染
   */
  stop() {
    if (!this.isRunning) return;
    this.isRunning = false;
    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
      this.animationFrameId = null;
    }
    console.log('[BlackHole] 渲染停止');
  }

  /**
   * 获取性能统计
   */
  getStats() {
    return this.performanceMonitor.getStats();
  }

  /**
   * 生成性能报告
   */
  generateReport() {
    return this.performanceMonitor.generateReport();
  }

  /**
   * 创建 Canvas 元素
   */
  createCanvas() {
    const canvas = document.createElement('canvas');
    canvas.style.position = 'fixed';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.zIndex = '-1';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    document.body.appendChild(canvas);
    return canvas;
  }

  /**
   * 销毁渲染器
   */
  destroy() {
    this.stop();
    this.interactionManager.destroy();
    this.particleSystem.destroy();
    this.webGLManager.destroy();
    if (this.canvas.parentNode) {
      this.canvas.parentNode.removeChild(this.canvas);
    }
    console.log('[BlackHole] 渲染器已销毁');
  }
}

export default BlackHoleRenderer;
