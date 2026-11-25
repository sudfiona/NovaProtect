<?php
/**
 * 黑洞系统 PHP 集成方案
 * 
 * 使用方法:
 * 1. 复制整个 blackhole-system 文件夹到你的项目目录
 * 2. 在你的 PHP 页面中包含这个文件: require_once 'blackhole-system/php-integration.php';
 * 3. 调用 render_blackhole() 或使用 BlackHoleIntegration 类
 * 
 * 示例:
 * <?php
 *   require_once 'blackhole-system/php-integration.php';
 *   render_blackhole([
 *     'quality' => 'auto',
 *     'show_performance' => true,
 *   ]);
 * ?>
 */

class BlackHoleIntegration {
  private $config = [];
  private $basePath = '';

  public function __construct($options = []) {
    $this->basePath = dirname(__FILE__);
    $this->config = $this->mergeConfig($this->getDefaultConfig(), $options);
  }

  /**
   * 获取默认配置
   */
  private function getDefaultConfig() {
    return [
      'quality' => 'auto',
      'show_performance' => false,
      'show_title' => true,
      'show_subtitle' => true,
      'custom_css' => '',
      'custom_js' => '',
      'canvas_id' => 'blackhole-canvas',
      'fps_counter_id' => 'fps-counter',
      'responsive' => true,
      'touch_enabled' => true,
      'interaction_enabled' => true,
      'particles' => [
        'count' => 50000,
        'emission_rate' => 1000,
        'lifespan' => 8000,
      ],
      'blackhole' => [
        'radius' => 2.0,
        'mass' => 1000,
        'rotation_speed' => 0.3,
      ],
      'lighting' => [
        'ambient_intensity' => 0.3,
        'light_intensity' => 1.5,
        'glow_intensity' => 0.8,
      ],
    ];
  }

  /**
   * 合并配置
   */
  private function mergeConfig($base, $override) {
    foreach ($override as $key => $value) {
      if (is_array($value) && isset($base[$key]) && is_array($base[$key])) {
        $base[$key] = $this->mergeConfig($base[$key], $value);
      } else {
        $base[$key] = $value;
      }
    }
    return $base;
  }

  /**
   * 渲染 CSS
   */
  public function renderCSS() {
    $cssPath = $this->basePath . '/styles/blackhole.css';
    if (!file_exists($cssPath)) {
      return "<!-- CSS 文件不存在: $cssPath -->";
    }

    $css = file_get_contents($cssPath);
    if ($this->config['custom_css']) {
      $css .= "\n" . $this->config['custom_css'];
    }

    return "<style>\n$css\n</style>";
  }

  /**
   * 渲染 HTML
   */
  public function renderHTML() {
    $html = '<canvas id="' . htmlspecialchars($this->config['canvas_id']) . '"></canvas>' . "\n";
    
    if ($this->config['show_performance']) {
      $html .= $this->renderPerformancePanel();
    }

    if ($this->config['show_title'] || $this->config['show_subtitle']) {
      $html .= $this->renderHeroSection();
    }

    return $html;
  }

  /**
   * 渲染性能面板
   */
  private function renderPerformancePanel() {
    return <<<'HTML'
    <div class="performance-info">
      <div>
        <span class="label">FPS:</span>
        <span class="value" id="fps-value">--</span>
      </div>
      <div>
        <span class="label">Frame Time:</span>
        <span class="value" id="frame-time">--ms</span>
      </div>
      <div>
        <span class="label">Particles:</span>
        <span class="value" id="particle-count">--</span>
      </div>
      <div>
        <span class="label">Memory:</span>
        <span class="value" id="memory">--MB</span>
      </div>
      <div>
        <span class="label">Quality:</span>
        <span class="value" id="quality">--</span>
      </div>
    </div>
HTML;
  }

  /**
   * 渲染英雄部分
   */
  private function renderHeroSection() {
    $title = $this->config['show_title'] ? '<h1 class="hero-title">🌌 BLACK HOLE</h1>' : '';
    $subtitle = $this->config['show_subtitle'] ? '<p class="hero-subtitle">移动鼠标或触摸来互动 • Move your mouse or touch to interact</p>' : '';

    return <<<HTML
    <div class="content-layer">
      <div class="hero-section">
        $title
        $subtitle
      </div>
    </div>
HTML;
  }

  /**
   * 渲染脚本
   */
  public function renderJS() {
    $config = json_encode([
      'quality' => $this->config['quality'],
      'config' => [
        'debug' => ['enabled' => false],
        'performance' => [
          'enabled' => true,
          'showFPS' => $this->config['show_performance'],
          'fpsUpdateInterval' => 500,
          'adaptiveFrameRate' => true,
        ],
        'particles' => $this->config['particles'],
        'blackhole' => $this->config['blackhole'],
        'lighting' => $this->config['lighting'],
        'interaction' => [
          'enabled' => $this->config['interaction_enabled'],
          'sensitivity' => 1.0,
          'damping' => 0.92,
        ],
      ],
    ], JSON_UNESCAPED_SLASHES);

    $performancePanel = $this->config['show_performance'] ? $this->getPerformancePanelScript() : '';

    return <<<JS
    <script type="module">
      import { BlackHoleRenderer } from './blackhole-system/core/BlackHoleRenderer.js';
      
      const renderer = new BlackHoleRenderer($config);
      renderer.start();
      
      $performancePanel

      window.addEventListener('beforeunload', () => {
        renderer.destroy();
      });

      document.addEventListener('touchmove', (e) => {
        if (e.target.tagName === 'CANVAS') {
          e.preventDefault();
        }
      }, { passive: false });
    </script>
JS;
  }

  /**
   * 获取性能面板脚本
   */
  private function getPerformancePanelScript() {
    return <<<'JS'
      setInterval(() => {
        const stats = renderer.getStats();
        const fpsEl = document.getElementById('fps-value');
        const frameTimeEl = document.getElementById('frame-time');
        const particleEl = document.getElementById('particle-count');
        const memoryEl = document.getElementById('memory');
        const qualityEl = document.getElementById('quality');

        if (fpsEl) fpsEl.textContent = Math.round(stats.fps);
        if (frameTimeEl) frameTimeEl.textContent = stats.frameTime.toFixed(1);
        if (particleEl) particleEl.textContent = renderer.particleSystem?.activeParticles || 0;
        if (memoryEl) memoryEl.textContent = stats.memory.jsHeapSize.toFixed(1);
        if (qualityEl) qualityEl.textContent = renderer.performanceMonitor.getPerformanceLevel().toUpperCase();
      }, 500);
JS;
  }

  /**
   * 完整渲染（包括 head 中的资源）
   */
  public function renderComplete() {
    return <<<HTML
    <!-- Black Hole System CSS -->
    {$this->renderCSS()}

    <!-- Black Hole System HTML -->
    <div id="blackhole-wrapper">
      {$this->renderHTML()}
    </div>

    <!-- Black Hole System JS -->
    {$this->renderJS()}
HTML;
  }

  /**
   * 获取配置
   */
  public function getConfig() {
    return $this->config;
  }

  /**
   * 更新配置
   */
  public function setConfig($key, $value) {
    if (is_array($key)) {
      $this->config = $this->mergeConfig($this->config, $key);
    } else {
      $this->config[$key] = $value;
    }
  }
}

/**
 * 便利函数：直接渲染黑洞系统
 */
function render_blackhole($options = []) {
  $integration = new BlackHoleIntegration($options);
  echo $integration->renderComplete();
}

/**
 * 便利函数：仅渲染 CSS（用于在 <head> 中调用）
 */
function render_blackhole_css($options = []) {
  $integration = new BlackHoleIntegration($options);
  echo $integration->renderCSS();
}

/**
 * 便利函数：仅渲染 HTML（用于在 <body> 中调用）
 */
function render_blackhole_html($options = []) {
  $integration = new BlackHoleIntegration($options);
  echo $integration->renderHTML();
}

/**
 * 便利函数：仅渲染 JS（用于在 <body> 底部调用）
 */
function render_blackhole_js($options = []) {
  $integration = new BlackHoleIntegration($options);
  echo $integration->renderJS();
}

// 仅当直接访问此文件时返回 JSON 配置
if (basename($_SERVER['PHP_SELF']) === basename(__FILE__)) {
  header('Content-Type: application/json; charset=utf-8');
  
  $integration = new BlackHoleIntegration($_GET);
  echo json_encode([
    'status' => 'success',
    'message' => 'Black Hole System is ready for integration',
    'config' => $integration->getConfig(),
    'example' => [
      'basic' => '<?php require_once "blackhole-system/php-integration.php"; render_blackhole(); ?>',
      'advanced' => '<?php require_once "blackhole-system/php-integration.php"; render_blackhole(["quality" => "high", "show_performance" => true]); ?>',
      'separated' => [
        'css' => '<?php require_once "blackhole-system/php-integration.php"; render_blackhole_css(); ?>',
        'html' => '<?php require_once "blackhole-system/php-integration.php"; render_blackhole_html(); ?>',
        'js' => '<?php require_once "blackhole-system/php-integration.php"; render_blackhole_js(); ?>',
      ],
    ],
  ]);
  exit;
}
