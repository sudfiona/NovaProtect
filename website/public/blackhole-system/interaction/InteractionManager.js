/**
 * 交互管理器
 * 处理鼠标、触摸、键盘交互
 */

export class InteractionManager {
  constructor(canvas, options = {}) {
    this.canvas = canvas;
    this.options = options;
    
    // 鼠标状态
    this.mouse = {
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
      down: false,
      worldPos: [0, 0, 0],
    };

    // 触摸状态
    this.touch = {
      active: false,
      startX: 0,
      startY: 0,
      currentX: 0,
      currentY: 0,
      count: 0,
    };

    // 交互参数
    this.sensitivity = options.sensitivity || 1.0;
    this.damping = options.damping || 0.92;
    this.attractionRadius = options.attractionRadius || 15;
    this.trackingSmoothness = options.trackingSmoothness || 0.15;

    // 相机参数
    this.cameraVelocity = [0, 0, 0];
    this.targetRotation = [0, 0];
    this.currentRotation = [0, 0];

    this.registerEventListeners();
  }

  /**
   * 注册事件监听
   */
  registerEventListeners() {
    // 鼠标事件
    this.canvas.addEventListener('mousemove', this.onMouseMove.bind(this));
    this.canvas.addEventListener('mousedown', this.onMouseDown.bind(this));
    this.canvas.addEventListener('mouseup', this.onMouseUp.bind(this));
    this.canvas.addEventListener('mouseleave', this.onMouseLeave.bind(this));
    this.canvas.addEventListener('wheel', this.onWheel.bind(this), { passive: false });

    // 触摸事件
    this.canvas.addEventListener('touchstart', this.onTouchStart.bind(this));
    this.canvas.addEventListener('touchmove', this.onTouchMove.bind(this), { passive: false });
    this.canvas.addEventListener('touchend', this.onTouchEnd.bind(this));

    // 双指缩放
    this.canvas.addEventListener('gesturechange', this.onGestureChange.bind(this));

    // 键盘事件
    document.addEventListener('keydown', this.onKeyDown.bind(this));
    document.addEventListener('keyup', this.onKeyUp.bind(this));

    // 窗口事件
    window.addEventListener('blur', this.onWindowBlur.bind(this));
  }

  /**
   * 鼠标移动
   */
  onMouseMove(event) {
    const rect = this.canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    this.mouse.vx = (x - this.mouse.x) * this.sensitivity;
    this.mouse.vy = (y - this.mouse.y) * this.sensitivity;

    this.mouse.x = x;
    this.mouse.y = y;

    // 转换为标准化坐标
    this.mouse.worldPos = this.screenToWorld(x, y);
  }

  /**
   * 鼠标按下
   */
  onMouseDown(event) {
    this.mouse.down = true;
  }

  /**
   * 鼠标抬起
   */
  onMouseUp(event) {
    this.mouse.down = false;
    // 鼠标释放时保持速度
    this.cameraVelocity[0] = this.mouse.vx * 0.01;
    this.cameraVelocity[1] = this.mouse.vy * 0.01;
  }

  /**
   * 鼠标离开
   */
  onMouseLeave(event) {
    this.mouse.down = false;
  }

  /**
   * 滚轮事件
   */
  onWheel(event) {
    event.preventDefault();
    
    const zoomDelta = event.deltaY > 0 ? 1.1 : 0.9;
    this.cameraVelocity[2] *= zoomDelta;
  }

  /**
   * 触摸开始
   */
  onTouchStart(event) {
    if (event.touches.length === 1) {
      const touch = event.touches[0];
      this.touch.active = true;
      this.touch.startX = touch.clientX;
      this.touch.startY = touch.clientY;
      this.touch.currentX = touch.clientX;
      this.touch.currentY = touch.clientY;
      this.touch.count = 1;
    } else if (event.touches.length === 2) {
      // 双指缩放
      this.touch.count = 2;
    }
  }

  /**
   * 触摸移动
   */
  onTouchMove(event) {
    event.preventDefault();

    if (event.touches.length === 1) {
      const touch = event.touches[0];
      this.touch.currentX = touch.clientX;
      this.touch.currentY = touch.clientY;

      const dx = this.touch.currentX - this.touch.startX;
      const dy = this.touch.currentY - this.touch.startY;

      this.cameraVelocity[0] = dx * 0.01 * this.sensitivity;
      this.cameraVelocity[1] = dy * 0.01 * this.sensitivity;

    } else if (event.touches.length === 2) {
      // 双指缩放
      const touch1 = event.touches[0];
      const touch2 = event.touches[1];

      const dx = touch2.clientX - touch1.clientX;
      const dy = touch2.clientY - touch1.clientY;
      const distance = Math.sqrt(dx * dx + dy * dy);

      // 记录距离用于缩放
      if (this.touch.lastDistance) {
        const scaleFactor = distance / this.touch.lastDistance;
        this.cameraVelocity[2] *= scaleFactor;
      }

      this.touch.lastDistance = distance;
    }
  }

  /**
   * 触摸结束
   */
  onTouchEnd(event) {
    if (event.touches.length === 0) {
      this.touch.active = false;
      this.touch.count = 0;
      this.touch.lastDistance = null;
    }
  }

  /**
   * 手势改变（iOS）
   */
  onGestureChange(event) {
    const scaleFactor = event.scale;
    this.cameraVelocity[2] *= scaleFactor;
  }

  /**
   * 键盘按下
   */
  onKeyDown(event) {
    switch (event.key) {
      case 'ArrowUp':
        this.cameraVelocity[1] += 0.1;
        break;
      case 'ArrowDown':
        this.cameraVelocity[1] -= 0.1;
        break;
      case 'ArrowLeft':
        this.cameraVelocity[0] -= 0.1;
        break;
      case 'ArrowRight':
        this.cameraVelocity[0] += 0.1;
        break;
      case '+':
      case '=':
        this.cameraVelocity[2] *= 0.9;
        break;
      case '-':
      case '_':
        this.cameraVelocity[2] *= 1.1;
        break;
    }
  }

  /**
   * 键盘抬起
   */
  onKeyUp(event) {
    // 可在此处添加键盘抬起逻辑
  }

  /**
   * 窗口失焦
   */
  onWindowBlur() {
    this.mouse.down = false;
    this.touch.active = false;
  }

  /**
   * 屏幕坐标转换为世界坐标
   */
  screenToWorld(screenX, screenY, distance = 10) {
    const rect = this.canvas.getBoundingClientRect();
    const x = (screenX / rect.width) * 2 - 1;
    const y = -(screenY / rect.height) * 2 + 1;

    return [x * distance, y * distance, -distance];
  }

  /**
   * 更新交互
   */
  update(deltaTime) {
    // 应用阻尼
    this.cameraVelocity[0] *= this.damping;
    this.cameraVelocity[1] *= this.damping;
    this.cameraVelocity[2] *= this.damping;

    // 应用鼠标速度（如果按下）
    if (this.mouse.down) {
      this.cameraVelocity[0] = this.mouse.vx * 0.01 * this.sensitivity;
      this.cameraVelocity[1] = this.mouse.vy * 0.01 * this.sensitivity;
    }

    // 重置鼠标速度
    this.mouse.vx = 0;
    this.mouse.vy = 0;
  }

  /**
   * 获取交互数据
   */
  getInteractionData() {
    return {
      mouse: { ...this.mouse },
      touch: { ...this.touch },
      velocity: [...this.cameraVelocity],
    };
  }

  /**
   * 清理资源
   */
  destroy() {
    this.canvas.removeEventListener('mousemove', this.onMouseMove);
    this.canvas.removeEventListener('mousedown', this.onMouseDown);
    this.canvas.removeEventListener('mouseup', this.onMouseUp);
    this.canvas.removeEventListener('mouseleave', this.onMouseLeave);
    this.canvas.removeEventListener('wheel', this.onWheel);

    this.canvas.removeEventListener('touchstart', this.onTouchStart);
    this.canvas.removeEventListener('touchmove', this.onTouchMove);
    this.canvas.removeEventListener('touchend', this.onTouchEnd);

    this.canvas.removeEventListener('gesturechange', this.onGestureChange);

    document.removeEventListener('keydown', this.onKeyDown);
    document.removeEventListener('keyup', this.onKeyUp);

    window.removeEventListener('blur', this.onWindowBlur);
  }
}

export default InteractionManager;
