/**
 * NovaProtect 官网黑洞集成模块
 * 
 * 兼容现有的 event-horizon.js，提供增强版本
 * 支持主题切换、高性能渲染、粒子效果
 * 
 * 使用方法：
 * <script type="module">
 *   import { WebsiteBlackHole } from './integration/website-integration.js';
 *   const blackhole = new WebsiteBlackHole({
 *     canvas: document.querySelector('.blackhole-flow'),
 *     quality: 'auto',
 *     enableParticles: true,
 *   });
 *   blackhole.start();
 * </script>
 */

import { BlackHoleRenderer } from '../core/BlackHoleRenderer.js';
import { ParticleSystem } from '../particles/ParticleSystem.js';
import { WEBSITE_CONFIG } from '../config/website-config.js';

export class WebsiteBlackHole {
  constructor(options = {}) {
    // 合并配置：用户选项 > 官网配置 > 默认配置
    const mergedConfig = { ...WEBSITE_CONFIG, ...options };
    
    this.canvas = mergedConfig.canvas || document.querySelector(mergedConfig.website.canvasSelector);
    this.sceneContainer = this.canvas?.closest(mergedConfig.website.sceneSelector);
    this.enableParticles = mergedConfig.enableParticles !== false;
    this.quality = mergedConfig.quality || 'auto';
    this.theme = document.documentElement.dataset.theme || 'light';
    this.config = mergedConfig;

    this.renderer = null;
    this.particleSystem = null;
    this.animationFrame = null;
    this.isVisible = true;
    this.isMotionPaused = false;

    this.init();
  }

  /**
   * 初始化
   */
  init() {
    if (!this.canvas) {
      console.warn('[WebsiteBlackHole] Canvas 未找到');
      return;
    }

    // 建立主题监听
    this.observeThemeChanges();
    this.observeMotionPreferences();
    this.observeVisibility();

    // 建立 Intersection Observer
    this.observeIntersection();
  }

  /**
   * 监听主题改变
   */
  observeThemeChanges() {
    const root = document.documentElement;
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.attributeName === 'data-theme') {
          const newTheme = root.dataset.theme;
          if (newTheme !== this.theme) {
            this.theme = newTheme;
            this.updateTheme(newTheme);
          }
        }
      });
    });

    observer.observe(root, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });
  }

  /**
   * 监听 motion 首选项
   */
  observeMotionPreferences() {
    const root = document.documentElement;
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.attributeName === 'class') {
          const motionPaused = root.classList.contains('motion-paused');
          if (motionPaused !== this.isMotionPaused) {
            this.isMotionPaused = motionPaused;
            this.updatePlayState();
          }
        }
      });
    });

    observer.observe(root, {
      attributes: true,
      attributeFilter: ['class'],
    });
  }

  /**
   * 监听可见性
   */
  observeVisibility() {
    document.addEventListener('visibilitychange', () => {
      this.updatePlayState();
    });
  }

  /**
   * 监听可见性
   */
  observeIntersection() {
    const observer = new IntersectionObserver(
      ([entry]) => {
        this.isVisible = entry.isIntersecting;
        this.updatePlayState();
      },
      { threshold: 0.1 }
    );

    if (this.sceneContainer) {
      observer.observe(this.sceneContainer);
    }
  }

  /**
   * 应该播放吗？
   */
  shouldPlay() {
    return (
      this.theme === 'blackhole' &&
      !this.isMotionPaused &&
      !document.hidden &&
      this.isVisible
    );
  }

  /**
   * 更新播放状态
   */
  updatePlayState() {
    if (this.shouldPlay()) {
      this.start();
    } else {
      this.stop();
    }
  }

  /**
   * 更新主题
   */
  updateTheme(theme) {
    if (theme === 'blackhole' && !this.renderer) {
      this.start();
    } else if (theme !== 'blackhole' && this.renderer) {
      this.stop();
    }
  }

  /**
   * 启动渲染
   */
  start() {
    if (this.renderer) return;
    if (this.theme !== 'blackhole') return;

    // 创建完整黑洞系统 - 使用官网配置
    this.renderer = new BlackHoleRenderer({
      canvas: this.canvas,
      quality: this.quality,
      config: {
        debug: this.config.debug,
        performance: this.config.performance,
        particles: this.config.particles,
        blackhole: this.config.blackhole,
        lighting: this.config.lighting,
        camera: this.config.camera,
        interaction: this.config.interaction,
        responsive: this.config.responsive,
      },
    });

    this.renderer.start();
  }

  /**
   * 停止渲染
   */
  stop() {
    if (this.renderer) {
      this.renderer.stop();
      this.renderer.destroy();
      this.renderer = null;
    }

    if (this.particleSystem) {
      this.particleSystem.clear();
    }

    if (this.animationFrame) {
      cancelAnimationFrame(this.animationFrame);
      this.animationFrame = null;
    }
  }

  /**
   * 获取性能统计
   */
  getStats() {
    return this.renderer?.getStats() || null;
  }

  /**
   * 销毁
   */
  destroy() {
    this.stop();
    this.canvas = null;
    this.sceneContainer = null;
  }
}

/**
 * 兼容层：替换官网现有的 event-horizon.js
 * 如果需要完全替换，可以这样使用：
 * 
 * <script type="module">
 *   import { createWebsiteBlackHole } from './integration/website-integration.js';
 *   createWebsiteBlackHole();
 * </script>
 */
export function createWebsiteBlackHole(options = {}) {
  const blackhole = new WebsiteBlackHole(options);
  
  // 自动启动
  if (blackhole.shouldPlay()) {
    blackhole.start();
  }

  // 全局暴露
  window.__websiteBlackHole = blackhole;

  return blackhole;
}

export default WebsiteBlackHole;
