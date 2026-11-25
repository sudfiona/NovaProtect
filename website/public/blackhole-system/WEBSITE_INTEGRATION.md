# NovaProtect 官网黑洞系统集成指南

## 概述

黑洞系统为 NovaProtect 官网提供高性能的 WebGL 渲染背景效果。系统支持官网现有的主题切换（`data-theme="blackhole"`）、运动首选项（`motion-paused`）和响应式布局。

---

## 集成方案

### 方案 A：替换现有 event-horizon.js（推荐）

#### 1. 复制黑洞系统
```bash
cp -r blackhole-system/blackhole-system /path/to/website/public/
```

#### 2. 更新 HTML 页面

在 `website/public/index.php` 中，将第 171 行：
```php
<script defer src="/js/event-horizon.js?v=3"></script>
```

替换为：
```php
<script type="module" defer src="/blackhole-system/integration/website-integration.js"></script>
```

#### 3. 验证效果

访问官网，切换到黑洞主题（`data-theme="blackhole"`），应显示完整的黑洞粒子系统。

---

### 方案 B：并行运行（兼容现有代码）

如需同时保留原有 event-horizon.js，可在 website-integration.js 加载前初始化新系统：

```html
<!-- 保留原有效果（静态线流） -->
<script defer src="/js/event-horizon.js?v=3"></script>

<!-- 添加新系统（动态粒子） -->
<script type="module" defer>
  import { WebsiteBlackHole } from './blackhole-system/integration/website-integration.js';
  
  // 仅在黑洞主题启用新系统
  const blackhole = new WebsiteBlackHole({
    canvas: document.querySelector('.blackhole-flow'),
    quality: 'auto',
    enableParticles: true,
  });
  
  // 自动响应主题切换
  if (document.documentElement.dataset.theme === 'blackhole') {
    blackhole.start();
  }
</script>
```

---

## 主题适配

### 黑洞主题色系

新系统自动适配三个官网主题：

| 主题 | 色温 | 粒子配色 | 是否启用 |
|------|------|---------|---------|
| 玻璃（glass） | 冰蓝薰衣草 | 冷色系 | 否 |
| 波普（pop） | 珊瑚柠檬品红 | 暖色系 | 否 |
| **黑洞（blackhole）** | **冰蓝+磷光** | **青蓝系** | **是** |

### 配色方案

```javascript
colorPalette: [
  [0, 1, 1],      // 冰蓝 (cyan)
  [0, 0.5, 1],    // 深蓝 (blue)
  [0.5, 0.8, 1],  // 浅蓝 (light blue)
  [0.2, 1, 1],    // 青色 (aqua)
]
```

---

## 配置选项

```javascript
new WebsiteBlackHole({
  // Canvas 元素（默认: .blackhole-flow）
  canvas: document.querySelector('.blackhole-flow'),
  
  // 质量等级：auto | high | medium | low | mobile
  quality: 'auto',
  
  // 启用粒子系统
  enableParticles: true,
  
  // 自定义配置
  config: {
    // 粒子系统配置
    particles: {
      defaultCount: 30000,      // 粒子数量
      emissionRate: 500,        // 发射速率
      lifespan: 6000,           // 生命周期（毫秒）
      speedRange: [0.5, 2],     // 速度范围
      sizeRange: [0.5, 1.5],    // 大小范围
    },
    
    // 黑洞参数
    blackhole: {
      radius: 2.0,              // 半径
      mass: 500,                // 质量
      shadowIntensity: 0.7,     // 阴影强度
    },
    
    // 光照参数
    lighting: {
      ambientIntensity: 0.4,    // 环境光强度
      lightIntensity: 1.2,      // 光照强度
      glowIntensity: 0.9,       // 光晕强度
    },
  },
});
```

---

## 自动响应

系统会自动响应以下事件：

### 1. 主题切换
```javascript
// 当 data-theme 改变时，自动启用/禁用
document.documentElement.dataset.theme = 'blackhole';  // 启用
document.documentElement.dataset.theme = 'glass';      // 禁用
```

### 2. 运动首选项
```javascript
// 用户启用 prefers-reduced-motion 时自动暂停
document.documentElement.classList.add('motion-paused');
```

### 3. 页面可见性
```javascript
// 标签页失焦时自动暂停（节省 CPU）
document.hidden = true;  // 自动暂停
```

### 4. 视口可见性
```javascript
// 元素滚出视口时自动暂停
// 通过 IntersectionObserver 自动检测
```

---

## 性能优化

### 自适应质量

系统根据设备自动调整质量：

| 设备类型 | 分辨率 | FPS | 质量 |
|---------|-------|-----|------|
| 高端桌面 | 4K+ | 120 | high |
| 中端桌面 | 1440p | 60 | medium |
| 中端移动 | 1080p | 30-60 | low |
| 低端移动 | 720p | 30 | mobile |

### 自动降级

如果 FPS 低于 50 且波动大，系统自动降低粒子数。

```javascript
// 检查性能级别
const stats = blackhole.getStats();
console.log(stats.fps);  // 当前 FPS
console.log(stats.memory);  // 内存使用
```

---

## HTML 结构

官网应保持以下结构：

```html
<section class="hero" data-emil="hero">
  <!-- 黑洞 Canvas -->
  <div class="blackhole-scene" aria-hidden="true">
    <div class="blackhole-scene-art">
      <canvas class="blackhole-flow" width="1280" height="800"></canvas>
    </div>
  </div>
  
  <!-- 内容层（覆盖在黑洞上） -->
  <div class="hero-copy">
    <!-- 文本内容 -->
  </div>
  
  <!-- 右侧控制台 -->
  <div class="hero-visual">
    <!-- 控制台UI -->
  </div>
</section>
```

---

## CSS 样式

新系统不需要额外 CSS，兼容现有的 `theme-layout.css`。

如需自定义样式：

```css
/* Canvas 样式 */
.blackhole-flow {
  width: 100%;
  height: 100%;
  display: block;
}

/* 淡出效果 */
.blackhole-scene {
  opacity: 1;
  transition: opacity 0.3s ease;
}

.blackhole-scene.hidden {
  opacity: 0;
  pointer-events: none;
}
```

---

## 部署清单

- [ ] 复制 `blackhole-system/` 到官网目录
- [ ] 更新 `index.php` 中的脚本引用
- [ ] 验证主题切换正常工作
- [ ] 在桌面/移动设备上测试性能
- [ ] 验证黑洞主题可访问性
- [ ] 检查 DevTools 是否有错误

---

## 故障排查

### 黑洞不显示

**症状：** Canvas 存在但无内容

**排查：**
```javascript
// 检查主题
console.log(document.documentElement.dataset.theme);  // 应为 'blackhole'

// 检查 Canvas
console.log(document.querySelector('.blackhole-flow'));  // 应存在

// 检查 WebGL 支持
const canvas = document.querySelector('.blackhole-flow');
const gl = canvas?.getContext('webgl2') || canvas?.getContext('webgl');
console.log('WebGL 支持:', !!gl);
```

### 性能很低

**症状：** FPS < 30

**解决：**
1. 检查质量设置：`quality: 'low'`
2. 降低粒子数：`particles: { defaultCount: 10000 }`
3. 检查浏览器硬件加速是否启用

### 主题切换无效

**症状：** 切换主题时黑洞不启用/禁用

**排查：**
```javascript
// 确保主题切换代码触发了 MutationObserver
// 检查 data-theme 属性是否正确设置
document.documentElement.dataset.theme = 'blackhole';
```

---

## API 参考

### WebsiteBlackHole 类

```javascript
// 创建实例
const blackhole = new WebsiteBlackHole(options);

// 启动渲染
blackhole.start();

// 停止渲染
blackhole.stop();

// 获取统计信息
const stats = blackhole.getStats();
console.log(stats.fps);        // 当前 FPS
console.log(stats.frameTime);  // 平均帧时间
console.log(stats.memory);     // 内存使用

// 销毁实例
blackhole.destroy();
```

### 全局访问

```javascript
// 创建后可通过全局变量访问
window.__websiteBlackHole.getStats();
```

---

## 浏览器支持

| 浏览器 | 最低版本 | 支持 |
|-------|---------|------|
| Chrome | 90+ | ✅ |
| Firefox | 88+ | ✅ |
| Safari | 15+ | ✅ |
| Edge | 90+ | ✅ |
| iOS Safari | 14+ | ✅ |
| Android Chrome | 90+ | ✅ |

---

## 文件结构

```
website/
├── public/
│   ├── index.php
│   ├── js/
│   │   ├── event-horizon.js          (原有)
│   │   └── ...
│   ├── css/
│   │   ├── theme-layout.css          (兼容)
│   │   └── ...
│   └── blackhole-system/              (新增)
│       ├── core/
│       ├── particles/
│       ├── shaders/
│       ├── integration/
│       │   └── website-integration.js
│       └── ...
└── ...
```

---

## 相关文档

- [完整 API 参考](../API_REFERENCE.md)
- [PHP 集成指南](../INTEGRATION_GUIDE.md)
- [性能优化](../README.md#性能指标)

---

## 许可证

MIT License

---

## 支持

遇到问题？

1. 检查浏览器控制台错误
2. 查看 [故障排查](#故障排查) 部分
3. 阅读 [完整文档](../README.md)
