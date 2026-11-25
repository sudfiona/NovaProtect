/**
 * NovaProtect 官网黑洞系统配置
 * 
 * 该配置文件为官网特定定制，包含：
 * - 官网黑洞主题配色
 * - 性能优化参数
 * - 官网特定集成选项
 */

export const WEBSITE_CONFIG = {
  // 质量检测
  quality: 'auto',

  // 性能参数
  performance: {
    enabled: true,
    showFPS: false,
    fpsUpdateInterval: 500,
    adaptiveFrameRate: true,
    targetFPS: 60,
  },

  // 粒子系统 - 官网优化配置
  particles: {
    defaultCount: 30000,      // 官网标准粒子数
    emissionRate: 500,        // 每秒发射
    lifespan: 6000,          // 生命周期 6 秒
    speedRange: [0.5, 2],
    sizeRange: [0.5, 1.5],
    
    // 官网黑洞主题色系 - 冷色系 + 磷光
    colorPalette: [
      [0.0, 1.0, 1.0],       // 冰蓝 (Cyan)
      [0.0, 0.5, 1.0],       // 深蓝 (Blue)
      [0.5, 0.8, 1.0],       // 浅蓝 (Light Blue)
      [0.2, 1.0, 1.0],       // 青绿 (Aqua)
    ],

    gravity: [0, -1, 0],
    damping: 0.98,
  },

  // 黑洞参数
  blackhole: {
    radius: 2.0,
    mass: 500,                // 中等质量
    attractionRange: 20,
    rotationSpeed: 0.3,
    shadowIntensity: 0.7,
    accretionDiskThickness: 0.5,
    position: [0, 0, 0],
  },

  // 光照参数 - 冷色系光晕
  lighting: {
    ambientIntensity: 0.4,
    ambientColor: [0.2, 0.3, 0.5],  // 冷蓝环境光
    lightColor: [0.0, 1.0, 1.0],    // 冰蓝主光
    lightIntensity: 1.2,
    glowIntensity: 0.9,             // 强光晕效果
  },

  // 相机参数
  camera: {
    fov: 75,
    near: 0.1,
    far: 1000,
    position: [0, 5, 15],
    target: [0, 0, 0],
  },

  // 交互参数
  interaction: {
    enabled: true,
    sensitivity: 1.0,
    damping: 0.92,
    attractionRadius: 15,
    attractionStrength: 0.5,
  },

  // 响应式参数
  responsive: {
    breakpoints: {
      mobile: 480,
      tablet: 768,
      desktop: 1024,
    },
    
    // 质量规则（按分辨率和设备）
    qualityRules: {
      // 低端移动设备
      'mobile-low': {
        quality: 'mobile',
        particles: { defaultCount: 10000 },
        fps: 30,
      },
      
      // 标准移动设备
      'mobile-standard': {
        quality: 'low',
        particles: { defaultCount: 15000 },
        fps: 30,
      },
      
      // 高端移动设备
      'mobile-high': {
        quality: 'medium',
        particles: { defaultCount: 20000 },
        fps: 60,
      },
      
      // 平板设备
      'tablet': {
        quality: 'medium',
        particles: { defaultCount: 25000 },
        fps: 60,
      },
      
      // 标准桌面
      'desktop': {
        quality: 'high',
        particles: { defaultCount: 30000 },
        fps: 120,
      },
      
      // 高端桌面（4K）
      'desktop-4k': {
        quality: 'high',
        particles: { defaultCount: 50000 },
        fps: 120,
      },
    },
    
    orientationChange: true,
    windowResize: true,
  },

  // 调试选项
  debug: {
    enabled: false,
    showGLErrors: false,
    showStats: false,
    logging: false,
  },

  // 官网集成选项
  website: {
    // 仅在黑洞主题启用
    themeAttribute: 'data-theme',
    themeValue: 'blackhole',
    
    // 响应运动首选项
    motionPreferenceClass: 'motion-paused',
    
    // Canvas 选择器
    canvasSelector: '.blackhole-flow',
    
    // 场景容器
    sceneSelector: '.blackhole-scene',
    
    // 自动播放策略
    autoPlay: true,
    pauseWhenHidden: true,
    pauseWhenOutOfView: true,
    
    // 淡出效果
    fadeEffect: {
      enabled: true,
      duration: 300,  // 毫秒
    },
  },
};

export default WEBSITE_CONFIG;
