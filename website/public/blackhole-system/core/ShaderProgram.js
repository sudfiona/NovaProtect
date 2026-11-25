/**
 * Shader 程序管理器
 * 编译、链接、统一变量管理
 */

export class ShaderProgram {
  constructor(gl, vertexSource, fragmentSource, name = 'unknown') {
    this.gl = gl;
    this.name = name;
    this.program = null;
    this.uniforms = {};
    this.attributes = {};
    this.vertexSource = vertexSource;
    this.fragmentSource = fragmentSource;

    this.compile();
  }

  /**
   * 编译 Shader
   */
  compile() {
    const vertexShader = this.compileShader(this.vertexSource, this.gl.VERTEX_SHADER);
    const fragmentShader = this.compileShader(this.fragmentSource, this.gl.FRAGMENT_SHADER);

    if (!vertexShader || !fragmentShader) {
      return false;
    }

    this.program = this.gl.createProgram();
    this.gl.attachShader(this.program, vertexShader);
    this.gl.attachShader(this.program, fragmentShader);
    this.gl.linkProgram(this.program);

    if (!this.gl.getProgramParameter(this.program, this.gl.LINK_STATUS)) {
      console.error(`[${this.name}] Shader 链接失败:`, this.gl.getProgramInfoLog(this.program));
      return false;
    }

    this.gl.deleteShader(vertexShader);
    this.gl.deleteShader(fragmentShader);

    // 检查属性和统一变量
    this.detectAttributes();
    this.detectUniforms();

    return true;
  }

  /**
   * 编译单个 Shader
   */
  compileShader(source, type) {
    const shader = this.gl.createShader(type);
    this.gl.shaderSource(shader, source);
    this.gl.compileShader(shader);

    if (!this.gl.getShaderParameter(shader, this.gl.COMPILE_STATUS)) {
      const typeName = type === this.gl.VERTEX_SHADER ? '顶点' : '片段';
      console.error(`[${this.name}] ${typeName}Shader 编译失败:`, this.gl.getShaderInfoLog(shader));
      this.gl.deleteShader(shader);
      return null;
    }

    return shader;
  }

  /**
   * 检测属性
   */
  detectAttributes() {
    const count = this.gl.getProgramParameter(this.program, this.gl.ACTIVE_ATTRIBUTES);

    for (let i = 0; i < count; i++) {
      const attr = this.gl.getActiveAttrib(this.program, i);
      const location = this.gl.getAttribLocation(this.program, attr.name);
      this.attributes[attr.name] = {
        location,
        type: attr.type,
        size: attr.size,
      };
    }
  }

  /**
   * 检测统一变量
   */
  detectUniforms() {
    const count = this.gl.getProgramParameter(this.program, this.gl.ACTIVE_UNIFORMS);

    for (let i = 0; i < count; i++) {
      const uniform = this.gl.getActiveUniform(this.program, i);
      const location = this.gl.getUniformLocation(this.program, uniform.name);
      this.uniforms[uniform.name] = {
        location,
        type: uniform.type,
        size: uniform.size,
      };
    }
  }

  /**
   * 使用 Shader 程序
   */
  use() {
    this.gl.useProgram(this.program);
  }

  /**
   * 设置统一变量
   */
  setUniform(name, value) {
    const uniform = this.uniforms[name];
    if (!uniform) {
      console.warn(`[${this.name}] 统一变量 '${name}' 不存在`);
      return;
    }

    this.use();

    const { location, type } = uniform;

    switch (type) {
      case this.gl.FLOAT:
        this.gl.uniform1f(location, value);
        break;
      case this.gl.INT:
      case this.gl.SAMPLER_2D:
      case this.gl.SAMPLER_CUBE:
        this.gl.uniform1i(location, value);
        break;
      case this.gl.FLOAT_VEC2:
        this.gl.uniform2fv(location, value);
        break;
      case this.gl.FLOAT_VEC3:
        this.gl.uniform3fv(location, value);
        break;
      case this.gl.FLOAT_VEC4:
        this.gl.uniform4fv(location, value);
        break;
      case this.gl.FLOAT_MAT2:
        this.gl.uniformMatrix2fv(location, false, value);
        break;
      case this.gl.FLOAT_MAT3:
        this.gl.uniformMatrix3fv(location, false, value);
        break;
      case this.gl.FLOAT_MAT4:
        this.gl.uniformMatrix4fv(location, false, value);
        break;
      default:
        console.warn(`[${this.name}] 未知的统一变量类型: ${type}`);
    }
  }

  /**
   * 批量设置统一变量
   */
  setUniforms(uniforms) {
    for (const [name, value] of Object.entries(uniforms)) {
      this.setUniform(name, value);
    }
  }

  /**
   * 获取属性位置
   */
  getAttribLocation(name) {
    return this.attributes[name]?.location ?? -1;
  }

  /**
   * 获取统一变量位置
   */
  getUniformLocation(name) {
    return this.uniforms[name]?.location ?? null;
  }

  /**
   * 销毁程序
   */
  destroy() {
    if (this.program) {
      this.gl.deleteProgram(this.program);
      this.program = null;
    }
  }
}

export default ShaderProgram;
