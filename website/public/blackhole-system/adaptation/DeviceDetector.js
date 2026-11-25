/**
 * 设备检测和性能缩放系统
 * 自动检测设备能力并调整渲染质量
 */

export class DeviceDetector {
  static detect() {
    return {
      isMobile: this.isMobile(),
      isTablet: this.isTablet(),
      isDesktop: !this.isMobile() && !this.isTablet(),
      deviceType: this.getDeviceType(),
      cpuCores: navigator.hardwareConcurrency || 4,
      deviceMemory: navigator.deviceMemory || 4,
      gpu: this.detectGPU(),
      connectionType: this.getConnectionType(),
    };
  }

  static isMobile() {
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
  }

  static isTablet() {
    return /iPad|Android/i.test(navigator.userAgent) && !/iPhone/i.test(navigator.userAgent);
  }

  static getDeviceType() {
    if (this.isMobile()) return 'mobile';
    if (this.isTablet()) return 'tablet';
    return 'desktop';
  }

  static detectGPU() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'unknown';

    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (debugInfo) {
      return gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    }
    return 'unknown';
  }

  static getConnectionType() {
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!connection) return 'unknown';
    return connection.effectiveType || 'unknown';
  }

  static getPerformanceScore() {
    const device = this.detect();
    let score = 50;

    // CPU 评分
    score += device.cpuCores * 5;

    // 内存评分
    score += device.deviceMemory * 5;

    // 设备类型
    if (device.isDesktop) score += 20;
    else if (device.isTablet) score -= 10;
    else if (device.isMobile) score -= 20;

    // 网络连接
    if (device.connectionType === '4g') score += 10;
    else if (device.connectionType === '3g') score -= 10;
    else if (device.connectionType === '2g') score -= 20;

    return Math.min(100, Math.max(0, score));
  }
}

/**
 * 性能缩放系统
 * 根据设备性能动态调整参数
 */
export class PerformanceScaler {
  static scaleQualityByPerformance(baseConfig) {
    const score = DeviceDetector.getPerformanceScore();

    if (score >= 80) {
      return { quality: 'high', multiplier: 1.2 };
    } else if (score >= 60) {
      return { quality: 'medium', multiplier: 1.0 };
    } else if (score >= 40) {
      return { quality: 'low', multiplier: 0.75 };
    } else {
      return { quality: 'mobile', multiplier: 0.5 };
    }
  }

  static scaleParticles(baseCount, multiplier) {
    return Math.floor(baseCount * multiplier);
  }

  static scaleResolution(multiplier) {
    return Math.max(0.5, Math.min(1.0, multiplier));
  }

  static scaleFPS(multiplier) {
    if (multiplier >= 1.0) return 120;
    if (multiplier >= 0.75) return 60;
    if (multiplier >= 0.5) return 30;
    return 15;
  }
}

/**
 * 响应式管理系统
 * 处理窗口大小、方向改变、DPI 改变
 */
export class ResponsiveManager {
  constructor(callback) {
    this.callback = callback;
    this.lastWidth = window.innerWidth;
    this.lastHeight = window.innerHeight;
    this.lastOrientation = window.innerHeight > window.innerWidth ? 'portrait' : 'landscape';

    this.setupListeners();
  }

  setupListeners() {
    window.addEventListener('resize', () => this.onResize());
    window.addEventListener('orientationchange', () => this.onOrientationChange());
    
    // 监听 DPI 改变
    if (window.matchMedia) {
      const dprQuery = window.matchMedia(`(resolution: ${window.devicePixelRatio}dppx)`);
      dprQuery.addListener(() => this.onDPRChange());
    }
  }

  onResize() {
    const newWidth = window.innerWidth;
    const newHeight = window.innerHeight;

    if (newWidth !== this.lastWidth || newHeight !== this.lastHeight) {
      this.lastWidth = newWidth;
      this.lastHeight = newHeight;

      this.callback({
        type: 'resize',
        width: newWidth,
        height: newHeight,
        breakpoint: this.getBreakpoint(newWidth),
      });
    }
  }

  onOrientationChange() {
    const newOrientation = window.innerHeight > window.innerWidth ? 'portrait' : 'landscape';

    if (newOrientation !== this.lastOrientation) {
      this.lastOrientation = newOrientation;

      this.callback({
        type: 'orientation',
        orientation: newOrientation,
      });
    }
  }

  onDPRChange() {
    this.callback({
      type: 'dpr',
      dpr: window.devicePixelRatio,
    });
  }

  getBreakpoint(width) {
    if (width <= 480) return 'xs';
    if (width <= 768) return 'sm';
    if (width <= 1024) return 'md';
    if (width <= 1366) return 'lg';
    if (width <= 1920) return 'xl';
    return 'xxl';
  }

  destroy() {
    window.removeEventListener('resize', () => this.onResize());
    window.removeEventListener('orientationchange', () => this.onOrientationChange());
  }
}

export default {
  DeviceDetector,
  PerformanceScaler,
  ResponsiveManager,
};
