/**
 * NovaProtect 官网黑洞系统自动初始化
 * 
 * 该脚本在页面加载时自动初始化黑洞系统
 * - 自动检测黑洞主题
 * - 自动响应主题切换
 * - 自动响应运动首选项
 * - 自动适配设备和性能
 */

import { WebsiteBlackHole } from './website-integration.js';
import { WEBSITE_CONFIG } from '../config/website-config.js';

// 初始化全局黑洞实例
let globalBlackHole = null;

/**
 * 初始化黑洞系统
 */
function initializeBlackHole() {
  // 检查是否已初始化
  if (globalBlackHole) return;

  // 创建黑洞实例（使用官网配置）
  globalBlackHole = new WebsiteBlackHole({
    quality: WEBSITE_CONFIG.quality,
    enableParticles: true,
  });

  // 暴露到全局（方便调试）
  window.__novaprotect_blackhole = globalBlackHole;

  // 自动启动（如果条件满足）
  if (globalBlackHole.shouldPlay()) {
    globalBlackHole.start();
  }

  console.log('[NovaProtect] 黑洞系统已初始化');
}

/**
 * 页面加载完成后初始化
 */
function onDOMReady() {
  // 检查 Canvas 元素是否存在
  const canvas = document.querySelector('.blackhole-flow');
  if (!canvas) {
    console.warn('[NovaProtect] 黑洞 Canvas 元素未找到 (.blackhole-flow)');
    return;
  }

  // 初始化黑洞系统
  initializeBlackHole();
}

/**
 * 监听 DOM 变化，实时响应主题切换
 */
function observeThemeChanges() {
  const root = document.documentElement;
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.attributeName === 'data-theme') {
        const theme = root.dataset.theme;
        console.log(`[NovaProtect] 主题切换: ${theme}`);
      }
    });
  });

  observer.observe(root, {
    attributes: true,
    attributeFilter: ['data-theme'],
  });
}

/**
 * 页面可见性变化
 */
function observePageVisibility() {
  document.addEventListener('visibilitychange', () => {
    if (globalBlackHole) {
      if (document.hidden) {
        console.log('[NovaProtect] 页面隐藏，黑洞暂停');
        globalBlackHole.stop();
      } else {
        console.log('[NovaProtect] 页面可见，黑洞恢复');
        if (globalBlackHole.shouldPlay()) {
          globalBlackHole.start();
        }
      }
    }
  });
}

/**
 * 页面卸载时清理
 */
function onBeforeUnload() {
  if (globalBlackHole) {
    globalBlackHole.destroy();
    globalBlackHole = null;
  }
}

/**
 * 启动初始化流程
 */
function startup() {
  // 如果 DOM 已加载，直接初始化
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onDOMReady);
  } else {
    onDOMReady();
  }

  // 建立监听
  observeThemeChanges();
  observePageVisibility();
  window.addEventListener('beforeunload', onBeforeUnload);

  console.log('[NovaProtect] 黑洞系统引导程序已启动');
}

// 立即启动
startup();

// 导出接口
export { WebsiteBlackHole, globalBlackHole as blackhole, WEBSITE_CONFIG };
