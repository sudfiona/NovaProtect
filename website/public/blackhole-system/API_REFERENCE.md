/**
 * 完整 API 文档
 * 黑洞系统全部可用 API
 */

// ============================================================
// 1. 主渲染器 API
// ============================================================

/**
 * BlackHoleRenderer - 主渲染器类
 * 
 * 使用示例:
 * const renderer = new BlackHoleRenderer({
 *   quality: 'auto',
 *   config: { ... }
 * });
 * renderer.start();
 */

// 构造函数选项
interface BlackHoleRendererOptions {
  canvas?: HTMLCanvasElement;        // 自定义 Canvas（默认创建）
  quality?: 'auto' | 'high' | 'medium' | 'low' | 'mobile';
  config?: Partial<DefaultConfig>;   // 自定义配置
}

// 实例方法
class BlackHoleRenderer {
  // 启动渲染
  start(): void

  // 停止渲染
  stop(): void

  // 获取性能统计
  getStats(): {
    fps: number;
    deltaTime: number;
    frameTime: number;
    maxFrameTime: number;
    minFrameTime: number;
    frameTimeVariance: number;
    memory: { jsHeapSize: number; jsHeapLimit: number; jsHeapUsage: number };
    rendering: { drawCalls: number; trianglesRendered: number; ... };
  }

  // 生成性能报告
  generateReport(): string

  // 销毁渲染器
  destroy(): void

  // 公共属性
  canvas: HTMLCanvasElement;
  config: DefaultConfig;
  gl: WebGLRenderingContext | WebGL2RenderingContext;
  performanceMonitor: PerformanceMonitor;
  particleSystem: ParticleSystem;
  interactionManager: InteractionManager;
}

// ============================================================
// 2. 粒子系统 API
// ============================================================

/**
 * ParticleSystem - 粒子系统
 * 
 * 使用示例:
 * particleSystem.emit({
 *   position: [0, 0, 0],
 *   count: 1000,
 *   speedRange: [1, 5]
 * });
 */

interface EmitterConfig {
  position: [number, number, number];       // 发射位置
  velocity?: [number, number, number];      // 初始速度
  count: number;                             // 发射数量
  speedRange?: [number, number];             // 速度范围
  sizeRange?: [number, number];              // 大小范围
  colorPalette?: Array<[number, number, number]>;  // 颜色列表
  lifespan?: number;                         // 生命周期（毫秒）
}

class ParticleSystem {
  // 发射粒子
  emit(config: EmitterConfig): void

  // 更新粒子
  update(deltaTime: number): void

  // 渲染粒子
  render(program: ShaderProgram): void

  // 清空粒子
  clear(): void

  // 销毁系统
  destroy(): void

  // 公共属性
  activeParticles: number;              // 活跃粒子数
  maxParticles: number;                 // 最大粒子数
  gravity: [number, number, number];    // 重力加速度
  damping: number;                      // 阻力系数
  attractionPoint: [number, number, number];  // 吸引点
  attractionStrength: number;           // 吸引强度
}

// ============================================================
// 3. 交互系统 API
// ============================================================

/**
 * InteractionManager - 交互管理
 * 
 * 自动处理：
 * - 鼠标移动、点击
 * - 触摸、多点触控
 * - 键盘输入
 * - 滚轮缩放
 */

class InteractionManager {
  // 获取交互数据
  getInteractionData(): {
    mouse: { x: number; y: number; vx: number; vy: number; down: boolean; worldPos: [number, number, number] };
    touch: { active: boolean; count: number; currentX: number; currentY: number };
    velocity: [number, number, number];
  }

  // 更新交互
  update(deltaTime: number): void

  // 销毁管理器
  destroy(): void

  // 公共属性
  sensitivity: number;                  // 灵敏度
  damping: number;                      // 阻尼系数
  cameraVelocity: [number, number, number];  // 相机速度
}

// ============================================================
// 4. 性能监控 API
// ============================================================

/**
 * PerformanceMonitor - 性能监控
 */

class PerformanceMonitor {
  // 更新帧计数
  update(): void

  // 获取平均帧时间（毫秒）
  getAverageFrameTime(): number

  // 获取最大帧时间（毫秒）
  getMaxFrameTime(): number

  // 获取最小帧时间（毫秒）
  getMinFrameTime(): number

  // 获取帧时间方差
  getFrameTimeVariance(): number

  // 获取性能等级
  getPerformanceLevel(): 'excellent' | 'good' | 'fair' | 'poor'

  // 是否应该降级
  shouldDegrade(): boolean

  // 是否应该升级
  shouldUpgrade(): boolean

  // 生成性能报告
  generateReport(): string

  // 获取完整统计
  getStats(): { fps: number; deltaTime: number; memory: {...}; rendering: {...} }

  // 重置统计
  resetStats(): void

  // 销毁监控器
  destroy(): void

  // 公共属性
  fps: number;                          // 当前 FPS
  deltaTime: number;                    // 帧增量时间
  enabled: boolean;                     // 是否启用
  showFPS: boolean;                     // 是否显示 FPS
}

// ============================================================
// 5. WebGL 管理器 API
// ============================================================

/**
 * WebGLManager - WebGL 上下文管理
 */

class WebGLManager {
  // 创建 Shader 程序
  createShaderProgram(
    vertexSource: string,
    fragmentSource: string,
    defines?: Record<string, any>
  ): WebGLProgram | null

  // 编译 Shader
  compileShader(source: string, type: GLenum, defines?: Record<string, any>): WebGLShader | null

  // 创建纹理
  createTexture(options: {
    width?: number;
    height?: number;
    format?: GLenum;
    type?: GLenum;
    data?: ArrayBufferView | null;
    magFilter?: GLenum;
    minFilter?: GLenum;
    generateMipmap?: boolean;
  }): WebGLTexture

  // 创建 Framebuffer
  createFramebuffer(width: number, height: number, options?: any): {
    framebuffer: WebGLFramebuffer;
    colorTexture: WebGLTexture;
    depthBuffer: WebGLRenderbuffer;
    width: number;
    height: number;
  }

  // 清空画布
  clear(r?: number, g?: number, b?: number, a?: number): void

  // 设置视口
  setViewport(x: number, y: number, width: number, height: number): void

  // 获取错误
  getErrors(): Array<{ error: GLenum; name: string; timestamp: number }>

  // 清空错误
  clearErrors(): void

  // 销毁上下文
  destroy(): void

  // 公共属性
  gl: WebGLRenderingContext | WebGL2RenderingContext;
  capabilities: { maxTextureSize: number; maxAnisotropy: number; ... };
  extensions: Record<string, any>;
}

// ============================================================
// 6. 设备检测 API
// ============================================================

/**
 * DeviceDetector - 设备检测
 */

class DeviceDetector {
  // 检测设备信息
  static detect(): {
    isMobile: boolean;
    isTablet: boolean;
    isDesktop: boolean;
    deviceType: 'mobile' | 'tablet' | 'desktop';
    cpuCores: number;
    deviceMemory: number;
    gpu: string;
    connectionType: string;
  }

  // 获取性能评分 (0-100)
  static getPerformanceScore(): number

  // 其他检测方法
  static isMobile(): boolean
  static isTablet(): boolean
  static getDeviceType(): string
  static detectGPU(): string
  static getConnectionType(): string
}

// ============================================================
// 7. 配置系统 API
// ============================================================

/**
 * 全局配置选项
 */

interface DefaultConfig {
  rendering: {
    quality: 'auto' | 'high' | 'medium' | 'low' | 'mobile';
    pixelRatio: number;
    vsync: boolean;
    maxFPS: number;
  };

  blackhole: {
    radius: number;
    mass: number;
    attractionRange: number;
    rotationSpeed: number;
    shadowIntensity: number;
    accretionDiskThickness: number;
  };

  particles: {
    countPresets: { high: number; medium: number; low: number; mobile: number };
    defaultCount: number;
    emissionRate: number;
    lifespan: number;
    speedRange: [number, number];
    sizeRange: [number, number];
    gravity: [number, number, number];
    damping: number;
    colorPalette: Array<[number, number, number]>;
  };

  lighting: {
    ambientIntensity: number;
    ambientColor: [number, number, number];
    lightColor: [number, number, number];
    lightIntensity: number;
    glowIntensity: number;
  };

  interaction: {
    enabled: boolean;
    sensitivity: number;
    damping: number;
    attractionRadius: number;
    attractionStrength: number;
  };

  camera: {
    fov: number;
    near: number;
    far: number;
    position: [number, number, number];
    target: [number, number, number];
  };

  responsive: {
    breakpoints: { mobile: number; tablet: number; desktop: number };
    qualityRules: Record<string, any>;
    orientationChange: boolean;
    windowResize: boolean;
  };

  performance: {
    enabled: boolean;
    showFPS: boolean;
    fpsUpdateInterval: number;
    adaptiveFrameRate: boolean;
    targetFPS: number;
  };

  debug: {
    enabled: boolean;
    showGLErrors: boolean;
    showStats: boolean;
    logging: boolean;
  };
}

// ============================================================
// 8. PHP 集成 API
// ============================================================

/**
 * PHP 类：BlackHoleIntegration
 * 
 * 使用示例:
 * $blackhole = new BlackHoleIntegration(['quality' => 'high']);
 * echo $blackhole->renderComplete();
 */

class BlackHoleIntegration {
  // 构造函数
  __construct(array $options = [])

  // 渲染 CSS
  public function renderCSS(): string

  // 渲染 HTML
  public function renderHTML(): string

  // 渲染 JS
  public function renderJS(): string

  // 完整渲染
  public function renderComplete(): string

  // 获取配置
  public function getConfig(): array

  // 设置配置
  public function setConfig(string|array $key, mixed $value): void
}

// 便利函数
function render_blackhole(array $options = []): void
function render_blackhole_css(array $options = []): void
function render_blackhole_html(array $options = []): void
function render_blackhole_js(array $options = []): void

// ============================================================
// 9. 类型定义
// ============================================================

type Vector2 = [number, number]
type Vector3 = [number, number, number]
type Vector4 = [number, number, number, number]
type Matrix4 = Float32Array

type Quality = 'auto' | 'high' | 'medium' | 'low' | 'mobile'
type DeviceType = 'mobile' | 'tablet' | 'desktop'
type PerformanceLevel = 'excellent' | 'good' | 'fair' | 'poor'

// ============================================================
// 10. 事件和回调
// ============================================================

// 交互事件
interface InteractionEvent {
  type: 'mousemove' | 'mousedown' | 'mouseup' | 'touch' | 'wheel' | 'keyboard'
  x?: number
  y?: number
  button?: number
  key?: string
  deltaY?: number
}

// 性能事件
interface PerformanceEvent {
  fps: number
  frameTime: number
  level: PerformanceLevel
  shouldDegrade?: boolean
  shouldUpgrade?: boolean
}

// 响应式事件
interface ResponsiveEvent {
  type: 'resize' | 'orientation' | 'dpr'
  width?: number
  height?: number
  orientation?: 'portrait' | 'landscape'
  dpr?: number
}
