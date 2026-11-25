/**
 * 黑洞系统全局配置
 * 生产级配置，支持动态调整
 */

export const DEFAULT_CONFIG = {
  // ============ 渲染配置 ============
  rendering: {
    // 质量预设: 'auto' | 'high' | 'medium' | 'low' | 'mobile'
    quality: 'auto',
    
    // 分辨率缩放
    pixelRatio: 1.0,
    
    // 垂直同步
    vsync: true,
    
    // 最大 FPS (0 表示无限制)
    maxFPS: 120,
  },

  // ============ 黑洞参数 ============
  blackhole: {
    // 黑洞半径 (相对单位)
    radius: 2.0,
    
    // 黑洞质量 (影响吸引力)
    mass: 1000,
    
    // 吸引范围
    attractionRange: 50,
    
    // 旋转速度
    rotationSpeed: 0.3,
    
    // 视界阴影强度 (0-1)
    shadowIntensity: 0.9,
    
    // 吸积盘厚度
    accretionDiskThickness: 0.3,
  },

  // ============ 粒子系统 ============
  particles: {
    // 质量等级下的粒子数
    countPresets: {
      high: 100000,
      medium: 50000,
      low: 25000,
      mobile: 15000,
    },
    
    // 默认质量下的粒子数
    defaultCount: 50000,
    
    // 粒子发射速率 (粒子/秒)
    emissionRate: 1000,
    
    // 粒子生命周期 (毫秒)
    lifespan: 8000,
    
    // 粒子速度范围 (单位/秒)
    speedRange: [1, 15],
    
    // 粒子大小范围
    sizeRange: [0.5, 3.0],
    
    // 重力加速度
    gravity: [0, -1, 0],
    
    // 阻力系数
    damping: 0.98,
    
    // 色调 (RGB 冷色系)
    colorPalette: [
      [0.0, 0.5, 1.0],   // 冷蓝
      [0.2, 0.3, 1.0],   // 深蓝
      [0.5, 0.0, 1.0],   // 紫色
      [0.0, 0.8, 1.0],   // 青色
    ],
  },

  // ============ 光影系统 ============
  lighting: {
    // 环境光强度
    ambientIntensity: 0.3,
    
    // 环境光颜色 (RGB)
    ambientColor: [0.1, 0.2, 0.3],
    
    // 主光源颜色 (冷色系)
    lightColor: [0.0, 0.7, 1.0],
    
    // 主光源强度
    lightIntensity: 1.5,
    
    // 光源方向
    lightDirection: [1, 1, -1],
    
    // 高光强度
    specularIntensity: 0.8,
    
    // 自发光强度
    emissiveIntensity: 1.2,
    
    // 光晕强度
    glowIntensity: 0.8,
  },

  // ============ 扭曲效果 ============
  distortion: {
    // 是否启用扭曲
    enabled: true,
    
    // 扭曲强度 (0-1)
    strength: 0.6,
    
    // 扭曲频率
    frequency: 1.0,
    
    // 扭曲动画速度
    animationSpeed: 0.5,
  },

  // ============ 交互系统 ============
  interaction: {
    // 是否启用交互
    enabled: true,
    
    // 鼠标/触摸灵敏度
    sensitivity: 1.0,
    
    // 阻尼系数 (0-1，越小阻尼越强)
    damping: 0.92,
    
    // 吸附半径 (相对单位)
    attractionRadius: 15,
    
    // 吸附强度
    attractionStrength: 0.8,
    
    // 鼠标追踪平滑系数
    trackingSmoothness: 0.15,
    
    // 长按延迟 (毫秒)
    pressDelay: 500,
    
    // 双击延迟 (毫秒)
    doubleClickDelay: 300,
  },

  // ============ 相机配置 ============
  camera: {
    // 视野角度 (度)
    fov: 75,
    
    // 近平面
    near: 0.1,
    
    // 远平面
    far: 1000,
    
    // 初始位置
    position: [0, 0, 10],
    
    // 看向点
    target: [0, 0, 0],
    
    // 相机速度 (用于自动转移)
    autoRotateSpeed: 0.1,
  },

  // ============ 响应式配置 ============
  responsive: {
    // 断点配置
    breakpoints: {
      mobile: 768,
      tablet: 1024,
      desktop: 1920,
    },
    
    // 质量降级规则
    qualityRules: {
      // 分辨率 > 4K 时降级
      '4k': { width: 3840, quality: 'high' },
      // 分辨率 1440p 时使用 high
      '1440p': { width: 2560, quality: 'high' },
      // 分辨率 1080p 时使用 medium
      '1080p': { width: 1920, quality: 'medium' },
      // 分辨率 720p 时使用 low
      '720p': { width: 1280, quality: 'low' },
      // 移动设备
      mobile: { width: 768, quality: 'mobile' },
    },
    
    // 自适应方向改变
    orientationChange: true,
    
    // 自适应窗口大小改变
    windowResize: true,
  },

  // ============ 设备检测 ============
  deviceDetection: {
    // 自动检测设备性能
    autoDetect: true,
    
    // 低端设备阈值 (GPU 评分)
    lowEndThreshold: 30,
    
    // 中端设备阈值
    midRangeThreshold: 60,
    
    // 高端设备阈值
    highEndThreshold: 90,
  },

  // ============ 性能监控 ============
  performance: {
    // 是否启用性能监控
    enabled: true,
    
    // 显示 FPS 计数器
    showFPS: false,
    
    // FPS 更新间隔 (毫秒)
    fpsUpdateInterval: 500,
    
    // 自适应帧率降级
    adaptiveFrameRate: true,
    
    // FPS 目标
    targetFPS: 60,
    
    // 自动调整延迟 (毫秒，0 禁用)
    autoAdjustDelay: 1000,
  },

  // ============ 调试选项 ============
  debug: {
    // 启用调试模式
    enabled: false,
    
    // 显示 WebGL 错误
    showGLErrors: true,
    
    // 显示性能统计
    showStats: false,
    
    // 显示边界框
    showBounds: false,
    
    // 记录日志
    logging: true,
    
    // 日志级别: 'trace' | 'debug' | 'info' | 'warn' | 'error'
    logLevel: 'info',
  },

  // ============ 音效配置（预留） ============
  audio: {
    enabled: false,
    masterVolume: 0.8,
    ambientVolume: 0.5,
  },
};

/**
 * 质量预设详细配置
 */
export const QUALITY_PRESETS = {
  high: {
    particles: {
      count: 100000,
      emissionRate: 1500,
    },
    pixelRatio: 1.0,
    distortion: { strength: 0.8, enabled: true },
    lighting: { glowIntensity: 1.0 },
    maxFPS: 120,
  },
  
  medium: {
    particles: {
      count: 50000,
      emissionRate: 1000,
    },
    pixelRatio: 0.9,
    distortion: { strength: 0.6, enabled: true },
    lighting: { glowIntensity: 0.8 },
    maxFPS: 120,
  },
  
  low: {
    particles: {
      count: 25000,
      emissionRate: 500,
    },
    pixelRatio: 0.75,
    distortion: { strength: 0.4, enabled: true },
    lighting: { glowIntensity: 0.6 },
    maxFPS: 60,
  },
  
  mobile: {
    particles: {
      count: 15000,
      emissionRate: 300,
    },
    pixelRatio: 0.6,
    distortion: { strength: 0.3, enabled: false },
    lighting: { glowIntensity: 0.4 },
    maxFPS: 30,
  },
};

/**
 * 合并配置对象
 */
export function mergeConfig(base, override) {
  return deepMerge(base, override);
}

/**
 * 深层合并对象
 */
function deepMerge(target, source) {
  const result = { ...target };
  
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = deepMerge(result[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }
  }
  
  return result;
}

export default DEFAULT_CONFIG;
