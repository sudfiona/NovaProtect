/**
 * WebGL 上下文管理器
 * 处理 WebGL 初始化、扩展检测、错误处理
 */

export class WebGLManager {
  constructor(canvas, options = {}) {
    this.canvas = canvas;
    this.gl = null;
    this.extensions = {};
    this.capabilities = {};
    this.errors = [];
    this.debug = options.debug || false;
    
    this.init(options);
  }

  /**
   * 初始化 WebGL 上下文
   */
  init(options) {
    try {
      // 创建 WebGL 2.0 或降级到 WebGL 1.0
      const contextAttributes = {
        alpha: true,
        antialias: true,
        depth: true,
        stencil: false,
        premultipliedAlpha: true,
        preserveDrawingBuffer: false,
        powerPreference: 'high-performance',
      };

      this.gl = this.canvas.getContext('webgl2', contextAttributes) ||
                this.canvas.getContext('webgl', contextAttributes);

      if (!this.gl) {
        throw new Error('WebGL 不支持');
      }

      // 检测 WebGL 版本
      this.webglVersion = this.gl.getParameter(this.gl.VERSION);
      this.shadingLanguageVersion = this.gl.getParameter(this.gl.SHADING_LANGUAGE_VERSION);

      this.log('info', `WebGL 版本: ${this.webglVersion}`);
      this.log('info', `着色器语言版本: ${this.shadingLanguageVersion}`);

      // 设置基础 WebGL 参数
      this.gl.clearColor(0, 0, 0, 1);
      this.gl.enable(this.gl.DEPTH_TEST);
      this.gl.enable(this.gl.BLEND);
      this.gl.blendFunc(this.gl.SRC_ALPHA, this.gl.ONE_MINUS_SRC_ALPHA);

      // 加载扩展
      this.loadExtensions();

      // 检测能力
      this.detectCapabilities();

      // 注册错误处理
      this.registerErrorHandler();

    } catch (error) {
      this.log('error', `WebGL 初始化失败: ${error.message}`);
      throw error;
    }
  }

  /**
   * 加载 WebGL 扩展
   */
  loadExtensions() {
    const extensionNames = [
      'OES_texture_float',
      'OES_texture_float_linear',
      'OES_texture_half_float',
      'OES_texture_half_float_linear',
      'OES_standard_derivatives',
      'EXT_texture_filter_anisotropic',
      'EXT_color_buffer_float',
      'WEBGL_color_buffer_float',
      'WEBGL_draw_buffers',
      'EXT_shader_texture_lod',
      'ANGLE_instanced_arrays',
    ];

    for (const name of extensionNames) {
      try {
        const ext = this.gl.getExtension(name);
        if (ext) {
          this.extensions[name] = ext;
          this.log('debug', `扩展已加载: ${name}`);
        }
      } catch (e) {
        this.log('debug', `扩展加载失败: ${name}`);
      }
    }
  }

  /**
   * 检测 WebGL 能力
   */
  detectCapabilities() {
    const gl = this.gl;

    this.capabilities = {
      maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
      maxCubeMapSize: gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
      maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
      maxVertexUniforms: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
      maxFragmentUniforms: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
      maxVaryings: gl.getParameter(gl.MAX_VARYING_VECTORS),
      maxRenderBufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
      supportsDepthTexture: !!this.extensions['WEBGL_depth_texture'],
      supportsFloatTexture: !!this.extensions['OES_texture_float'],
      supportsHalfFloatTexture: !!this.extensions['OES_texture_half_float'],
      supportsAnisotropic: !!this.extensions['EXT_texture_filter_anisotropic'],
      supportsDrawBuffers: !!this.extensions['WEBGL_draw_buffers'],
      maxAnisotropy: this.getMaxAnisotropy(),
    };

    this.log('info', 'WebGL 能力检测完成');
    this.log('debug', JSON.stringify(this.capabilities, null, 2));
  }

  /**
   * 获取最大各向异性滤波
   */
  getMaxAnisotropy() {
    const ext = this.extensions['EXT_texture_filter_anisotropic'];
    if (!ext) return 1;
    return this.gl.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT);
  }

  /**
   * 注册 WebGL 错误处理
   */
  registerErrorHandler() {
    const originalGetError = this.gl.getError.bind(this.gl);

    this.gl.getError = () => {
      const error = originalGetError();
      if (error !== this.gl.NO_ERROR) {
        const errorName = this.getErrorName(error);
        this.log('warn', `WebGL 错误: ${errorName} (${error})`);
        this.errors.push({ error, name: errorName, timestamp: Date.now() });
        
        // 保留最近 100 个错误
        if (this.errors.length > 100) {
          this.errors.shift();
        }
      }
      return error;
    };
  }

  /**
   * 获取 WebGL 错误名称
   */
  getErrorName(error) {
    const errorMap = {
      0: 'NO_ERROR',
      1280: 'INVALID_ENUM',
      1281: 'INVALID_VALUE',
      1282: 'INVALID_OPERATION',
      1285: 'OUT_OF_MEMORY',
      1286: 'INVALID_FRAMEBUFFER_OPERATION',
    };
    return errorMap[error] || 'UNKNOWN_ERROR';
  }

  /**
   * 创建 Shader 程序
   */
  createShaderProgram(vertexSource, fragmentSource, defines = {}) {
    const vs = this.compileShader(vertexSource, this.gl.VERTEX_SHADER, defines);
    const fs = this.compileShader(fragmentSource, this.gl.FRAGMENT_SHADER, defines);

    if (!vs || !fs) {
      return null;
    }

    const program = this.gl.createProgram();
    this.gl.attachShader(program, vs);
    this.gl.attachShader(program, fs);
    this.gl.linkProgram(program);

    if (!this.gl.getProgramParameter(program, this.gl.LINK_STATUS)) {
      const info = this.gl.getProgramInfoLog(program);
      this.log('error', `Shader 链接失败: ${info}`);
      this.gl.deleteProgram(program);
      return null;
    }

    this.gl.deleteShader(vs);
    this.gl.deleteShader(fs);

    return program;
  }

  /**
   * 编译 Shader
   */
  compileShader(source, type, defines = {}) {
    // 添加 define
    let defineCode = '';
    for (const [key, value] of Object.entries(defines)) {
      defineCode += `#define ${key} ${value}\n`;
    }

    // 添加 WebGL 版本
    const version = this.gl instanceof WebGL2RenderingContext ? '#version 300 es' : '#version 100';
    const fullSource = `${version}\n${defineCode}\n${source}`;

    const shader = this.gl.createShader(type);
    this.gl.shaderSource(shader, fullSource);
    this.gl.compileShader(shader);

    if (!this.gl.getShaderParameter(shader, this.gl.COMPILE_STATUS)) {
      const info = this.gl.getShaderInfoLog(shader);
      const typeName = type === this.gl.VERTEX_SHADER ? '顶点' : '片段';
      this.log('error', `${typeName}Shader 编译失败: ${info}`);
      this.gl.deleteShader(shader);
      return null;
    }

    return shader;
  }

  /**
   * 创建纹理
   */
  createTexture(options = {}) {
    const gl = this.gl;
    const texture = gl.createTexture();

    gl.bindTexture(gl.TEXTURE_2D, texture);

    const {
      width = 512,
      height = 512,
      format = gl.RGBA,
      type = gl.UNSIGNED_BYTE,
      data = null,
      magFilter = gl.LINEAR,
      minFilter = gl.LINEAR_MIPMAP_LINEAR,
      wrapS = gl.CLAMP_TO_EDGE,
      wrapT = gl.CLAMP_TO_EDGE,
      generateMipmap = true,
    } = options;

    gl.texImage2D(gl.TEXTURE_2D, 0, format, width, height, 0, format, type, data);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, magFilter);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, minFilter);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, wrapS);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, wrapT);

    if (generateMipmap) {
      gl.generateMipmap(gl.TEXTURE_2D);
    }

    gl.bindTexture(gl.TEXTURE_2D, null);

    return texture;
  }

  /**
   * 创建 FrameBuffer
   */
  createFramebuffer(width, height, options = {}) {
    const gl = this.gl;

    const framebuffer = gl.createFramebuffer();
    gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);

    const colorTexture = this.createTexture({
      width,
      height,
      format: options.format || gl.RGBA,
      type: options.type || gl.UNSIGNED_BYTE,
    });

    gl.framebufferTexture2D(
      gl.FRAMEBUFFER,
      gl.COLOR_ATTACHMENT0,
      gl.TEXTURE_2D,
      colorTexture,
      0
    );

    // 创建深度缓冲
    const depthBuffer = gl.createRenderbuffer();
    gl.bindRenderbuffer(gl.RENDERBUFFER, depthBuffer);
    gl.renderbufferStorage(gl.RENDERBUFFER, gl.DEPTH_COMPONENT16, width, height);
    gl.framebufferRenderbuffer(gl.FRAMEBUFFER, gl.DEPTH_ATTACHMENT, gl.RENDERBUFFER, depthBuffer);

    const status = gl.checkFramebufferStatus(gl.FRAMEBUFFER);
    if (status !== gl.FRAMEBUFFER_COMPLETE) {
      this.log('error', `Framebuffer 不完整: ${status}`);
    }

    gl.bindFramebuffer(gl.FRAMEBUFFER, null);

    return { framebuffer, colorTexture, depthBuffer, width, height };
  }

  /**
   * 创建 VAO (顶点数组对象)
   */
  createVAO() {
    if (this.gl instanceof WebGL2RenderingContext) {
      return this.gl.createVertexArray();
    }
    // WebGL 1.0 返回 null，使用 VAO 扩展处理
    return null;
  }

  /**
   * 清空上下文
   */
  clear(r = 0, g = 0, b = 0, a = 1) {
    this.gl.clearColor(r, g, b, a);
    this.gl.clear(this.gl.COLOR_BUFFER_BIT | this.gl.DEPTH_BUFFER_BIT);
  }

  /**
   * 设置视口
   */
  setViewport(x, y, width, height) {
    this.gl.viewport(x, y, width, height);
  }

  /**
   * 获取错误日志
   */
  getErrors() {
    return this.errors;
  }

  /**
   * 清空错误日志
   */
  clearErrors() {
    this.errors = [];
  }

  /**
   * 日志输出
   */
  log(level, message) {
    if (!this.debug && level === 'debug') return;
    
    const prefix = `[WebGL ${level.toUpperCase()}]`;
    switch (level) {
      case 'debug':
        console.debug(prefix, message);
        break;
      case 'info':
        console.info(prefix, message);
        break;
      case 'warn':
        console.warn(prefix, message);
        break;
      case 'error':
        console.error(prefix, message);
        break;
    }
  }

  /**
   * 销毁上下文
   */
  destroy() {
    this.gl = null;
    this.extensions = {};
    this.capabilities = {};
    this.errors = [];
  }
}

export default WebGLManager;
