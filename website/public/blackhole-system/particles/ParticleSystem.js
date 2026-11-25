/**
 * 粒子系统 - 管理粒子生命周期和物理
 */

export class ParticleSystem {
  constructor(gl, maxParticles = 50000) {
    this.gl = gl;
    this.maxParticles = maxParticles;
    
    // 粒子数据
    this.particles = [];
    this.activeParticles = 0;
    
    // GPU 缓冲
    this.positionBuffer = null;
    this.velocityBuffer = null;
    this.lifeBuffer = null;
    this.sizeBuffer = null;
    this.colorBuffer = null;
    
    this.vao = null;
    this.program = null;
    
    // 物理参数
    this.gravity = [0, -1, 0];
    this.damping = 0.98;
    this.attractionPoint = [0, 0, 0];
    this.attractionStrength = 0.5;
    
    this.init();
  }

  /**
   * 初始化粒子系统
   */
  init() {
    // 初始化粒子数组
    for (let i = 0; i < this.maxParticles; i++) {
      this.particles.push({
        position: [0, 0, 0],
        velocity: [0, 0, 0],
        life: 1.0,
        maxLife: 1.0,
        size: 1.0,
        color: [1, 1, 1],
        active: false,
      });
    }

    // 创建 GPU 缓冲
    this.positionBuffer = this.gl.createBuffer();
    this.velocityBuffer = this.gl.createBuffer();
    this.lifeBuffer = this.gl.createBuffer();
    this.sizeBuffer = this.gl.createBuffer();
    this.colorBuffer = this.gl.createBuffer();

    // 分配初始内存
    const positions = new Float32Array(this.maxParticles * 3);
    const velocities = new Float32Array(this.maxParticles * 3);
    const lives = new Float32Array(this.maxParticles);
    const sizes = new Float32Array(this.maxParticles);
    const colors = new Float32Array(this.maxParticles * 3);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.positionBuffer);
    this.gl.bufferData(this.gl.ARRAY_BUFFER, positions, this.gl.DYNAMIC_DRAW);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.velocityBuffer);
    this.gl.bufferData(this.gl.ARRAY_BUFFER, velocities, this.gl.DYNAMIC_DRAW);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.lifeBuffer);
    this.gl.bufferData(this.gl.ARRAY_BUFFER, lives, this.gl.DYNAMIC_DRAW);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.sizeBuffer);
    this.gl.bufferData(this.gl.ARRAY_BUFFER, sizes, this.gl.DYNAMIC_DRAW);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.colorBuffer);
    this.gl.bufferData(this.gl.ARRAY_BUFFER, colors, this.gl.DYNAMIC_DRAW);
  }

  /**
   * 发射粒子
   */
  emit(emitter) {
    const {
      position,
      velocity,
      count,
      speedRange = [1, 5],
      sizeRange = [1, 2],
      colorPalette = [[1, 1, 1]],
      lifespan = 5000,
    } = emitter;

    for (let i = 0; i < count; i++) {
      if (this.activeParticles >= this.maxParticles) break;

      const particle = this.particles[this.activeParticles];
      
      // 随机速度
      const speed = speedRange[0] + Math.random() * (speedRange[1] - speedRange[0]);
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.random() * Math.PI;

      particle.position = [...position];
      particle.velocity = [
        Math.sin(phi) * Math.cos(theta) * speed,
        Math.sin(phi) * Math.sin(theta) * speed,
        Math.cos(phi) * speed,
      ];

      // 随机大小
      particle.size = sizeRange[0] + Math.random() * (sizeRange[1] - sizeRange[0]);

      // 随机颜色
      const color = colorPalette[Math.floor(Math.random() * colorPalette.length)];
      particle.color = color;

      // 生命周期
      particle.maxLife = lifespan;
      particle.life = 1.0;
      particle.active = true;

      this.activeParticles++;
    }
  }

  /**
   * 更新粒子
   */
  update(deltaTime) {
    const dt = deltaTime;

    for (let i = 0; i < this.activeParticles; i++) {
      const particle = this.particles[i];

      if (!particle.active) continue;

      // 更新生命周期
      particle.life -= dt / (particle.maxLife / 1000);
      
      if (particle.life <= 0) {
        particle.active = false;
        // 交换到列表末尾，减少 activeParticles
        [this.particles[i], this.particles[this.activeParticles - 1]] = 
        [this.particles[this.activeParticles - 1], this.particles[i]];
        this.activeParticles--;
        i--;
        continue;
      }

      // 应用重力
      particle.velocity[1] += this.gravity[1] * dt;

      // 应用吸引力
      const dx = this.attractionPoint[0] - particle.position[0];
      const dy = this.attractionPoint[1] - particle.position[1];
      const dz = this.attractionPoint[2] - particle.position[2];
      const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);

      if (dist > 0.01) {
        const nx = dx / dist;
        const ny = dy / dist;
        const nz = dz / dist;

        particle.velocity[0] += nx * this.attractionStrength * dt;
        particle.velocity[1] += ny * this.attractionStrength * dt;
        particle.velocity[2] += nz * this.attractionStrength * dt;
      }

      // 应用阻力
      particle.velocity[0] *= this.damping;
      particle.velocity[1] *= this.damping;
      particle.velocity[2] *= this.damping;

      // 更新位置
      particle.position[0] += particle.velocity[0] * dt;
      particle.position[1] += particle.velocity[1] * dt;
      particle.position[2] += particle.velocity[2] * dt;
    }

    // 更新 GPU 缓冲
    this.updateBuffers();
  }

  /**
   * 更新 GPU 缓冲
   */
  updateBuffers() {
    const positions = new Float32Array(this.maxParticles * 3);
    const velocities = new Float32Array(this.maxParticles * 3);
    const lives = new Float32Array(this.maxParticles);
    const sizes = new Float32Array(this.maxParticles);
    const colors = new Float32Array(this.maxParticles * 3);

    for (let i = 0; i < this.activeParticles; i++) {
      const p = this.particles[i];

      positions[i * 3] = p.position[0];
      positions[i * 3 + 1] = p.position[1];
      positions[i * 3 + 2] = p.position[2];

      velocities[i * 3] = p.velocity[0];
      velocities[i * 3 + 1] = p.velocity[1];
      velocities[i * 3 + 2] = p.velocity[2];

      lives[i] = p.life;
      sizes[i] = p.size;

      colors[i * 3] = p.color[0];
      colors[i * 3 + 1] = p.color[1];
      colors[i * 3 + 2] = p.color[2];
    }

    // 上传到 GPU
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.positionBuffer);
    this.gl.bufferSubData(this.gl.ARRAY_BUFFER, 0, positions);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.velocityBuffer);
    this.gl.bufferSubData(this.gl.ARRAY_BUFFER, 0, velocities);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.lifeBuffer);
    this.gl.bufferSubData(this.gl.ARRAY_BUFFER, 0, lives);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.sizeBuffer);
    this.gl.bufferSubData(this.gl.ARRAY_BUFFER, 0, sizes);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.colorBuffer);
    this.gl.bufferSubData(this.gl.ARRAY_BUFFER, 0, colors);
  }

  /**
   * 渲染粒子
   */
  render(program) {
    if (this.activeParticles === 0) return;

    this.gl.useProgram(program.program);

    // 绑定属性
    const posLoc = program.getAttribLocation('aPosition');
    const velLoc = program.getAttribLocation('aVelocity');
    const lifeLoc = program.getAttribLocation('aLife');
    const sizeLoc = program.getAttribLocation('aSize');
    const colorLoc = program.getAttribLocation('aColor');

    // 位置
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.positionBuffer);
    this.gl.vertexAttribPointer(posLoc, 3, this.gl.FLOAT, false, 0, 0);
    this.gl.enableVertexAttribArray(posLoc);

    // 速度
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.velocityBuffer);
    this.gl.vertexAttribPointer(velLoc, 3, this.gl.FLOAT, false, 0, 0);
    this.gl.enableVertexAttribArray(velLoc);

    // 生命周期
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.lifeBuffer);
    this.gl.vertexAttribPointer(lifeLoc, 1, this.gl.FLOAT, false, 0, 0);
    this.gl.enableVertexAttribArray(lifeLoc);

    // 大小
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.sizeBuffer);
    this.gl.vertexAttribPointer(sizeLoc, 1, this.gl.FLOAT, false, 0, 0);
    this.gl.enableVertexAttribArray(sizeLoc);

    // 颜色
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.colorBuffer);
    this.gl.vertexAttribPointer(colorLoc, 3, this.gl.FLOAT, false, 0, 0);
    this.gl.enableVertexAttribArray(colorLoc);

    // 渲染
    this.gl.drawArrays(this.gl.POINTS, 0, this.activeParticles);
  }

  /**
   * 清空粒子
   */
  clear() {
    for (const p of this.particles) {
      p.active = false;
    }
    this.activeParticles = 0;
  }

  /**
   * 销毁
   */
  destroy() {
    this.gl.deleteBuffer(this.positionBuffer);
    this.gl.deleteBuffer(this.velocityBuffer);
    this.gl.deleteBuffer(this.lifeBuffer);
    this.gl.deleteBuffer(this.sizeBuffer);
    this.gl.deleteBuffer(this.colorBuffer);
  }
}

export default ParticleSystem;
