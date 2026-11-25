// 黑洞顶点着色器
export const BLACKHOLE_VERTEX_SHADER = `
#version 300 es
precision highp float;

in vec3 aPosition;
in vec3 aNormal;
in vec2 aTexCoord;

uniform mat4 uModelMatrix;
uniform mat4 uViewMatrix;
uniform mat4 uProjectionMatrix;
uniform mat4 uNormalMatrix;

out vec3 vPosition;
out vec3 vNormal;
out vec2 vTexCoord;
out vec4 vWorldPos;

void main() {
    vWorldPos = uModelMatrix * vec4(aPosition, 1.0);
    vPosition = vWorldPos.xyz;
    vNormal = normalize((uNormalMatrix * vec4(aNormal, 0.0)).xyz);
    vTexCoord = aTexCoord;
    
    gl_Position = uProjectionMatrix * uViewMatrix * vWorldPos;
}
`;

// 黑洞片段着色器
export const BLACKHOLE_FRAGMENT_SHADER = `
#version 300 es
precision highp float;

in vec3 vPosition;
in vec3 vNormal;
in vec2 vTexCoord;
in vec4 vWorldPos;

uniform vec3 uCameraPos;
uniform vec3 uLightDir;
uniform vec3 uLightColor;
uniform float uLightIntensity;
uniform float uTime;
uniform float uBlackholeRadius;
uniform float uShadowIntensity;
uniform float uAccretionDiskThickness;
uniform float uGlowIntensity;

// 冷色系调色板
uniform vec3 uColorPalette[4];

out vec4 FragColor;

// 噪声函数
float hash(vec3 p) {
    return fract(sin(dot(p, vec3(12.9898, 78.233, 45.164))) * 43758.5453);
}

float perlin(vec3 p) {
    vec3 i = floor(p);
    vec3 f = fract(p);
    f = f * f * (3.0 - 2.0 * f);
    
    float n000 = hash(i);
    float n100 = hash(i + vec3(1.0, 0.0, 0.0));
    float n010 = hash(i + vec3(0.0, 1.0, 0.0));
    float n110 = hash(i + vec3(1.0, 1.0, 0.0));
    float n001 = hash(i + vec3(0.0, 0.0, 1.0));
    float n101 = hash(i + vec3(1.0, 0.0, 1.0));
    float n011 = hash(i + vec3(0.0, 1.0, 1.0));
    float n111 = hash(i + vec3(1.0, 1.0, 1.0));
    
    float nx0 = mix(n000, n100, f.x);
    float nx1 = mix(n010, n110, f.x);
    float nxy0 = mix(nx0, nx1, f.y);
    
    float nx0z1 = mix(n001, n101, f.x);
    float nx1z1 = mix(n011, n111, f.x);
    float nxy1 = mix(nx0z1, nx1z1, f.y);
    
    return mix(nxy0, nxy1, f.z);
}

// 计算黑洞视界
float blackholeEffect(vec3 pos) {
    float dist = length(pos);
    
    // 视界阴影
    float shadow = smoothstep(uBlackholeRadius * 2.0, uBlackholeRadius, dist);
    shadow *= uShadowIntensity;
    
    // 吸积盘扭曲
    float diskDist = abs(pos.y);
    float disk = exp(-diskDist / uAccretionDiskThickness) * (1.0 - shadow);
    
    // 光晕效应
    float halo = exp(-dist * 0.3) * (1.0 - shadow);
    
    return disk + halo;
}

void main() {
    vec3 N = normalize(vNormal);
    vec3 L = normalize(uLightDir);
    vec3 V = normalize(uCameraPos - vPosition);
    
    // 基础光照
    float diffuse = max(dot(N, L), 0.0);
    vec3 R = reflect(-L, N);
    float specular = pow(max(dot(R, V), 0.0), 32.0);
    
    // 黑洞效果
    float bh = blackholeEffect(vPosition);
    
    // 颜色混合
    vec3 color = uColorPalette[0];
    color = mix(color, uColorPalette[1], diffuse);
    color = mix(color, uColorPalette[2], bh * 0.5);
    
    // 光照计算
    vec3 lightColor = uLightColor * uLightIntensity;
    vec3 finalColor = color * (0.3 + diffuse * 0.7) * lightColor;
    finalColor += specular * lightColor * 0.5;
    
    // 自发光
    finalColor += uColorPalette[3] * bh * uGlowIntensity;
    
    // 色调映射
    finalColor = finalColor / (finalColor + 1.0);
    finalColor = pow(finalColor, vec3(1.0 / 2.2));
    
    FragColor = vec4(finalColor, 1.0);
}
`;

// 粒子顶点着色器
export const PARTICLE_VERTEX_SHADER = `
#version 300 es
precision highp float;

in vec3 aPosition;
in vec3 aVelocity;
in float aLife;
in float aSize;
in vec3 aColor;

uniform mat4 uViewMatrix;
uniform mat4 uProjectionMatrix;
uniform vec3 uCameraPos;
uniform float uTime;

out float vLife;
out vec3 vColor;
out float vSize;

void main() {
    // 相对于相机的位置
    vec3 offset = aPosition - uCameraPos;
    vec4 viewPos = uViewMatrix * vec4(offset, 1.0);
    
    // 生命周期透明度
    vLife = aLife;
    vColor = aColor;
    vSize = aSize * (1.0 - aLife); // 渐变消失
    
    gl_Position = uProjectionMatrix * viewPos;
    gl_PointSize = vSize;
}
`;

// 粒子片段着色器
export const PARTICLE_FRAGMENT_SHADER = `
#version 300 es
precision highp float;

in float vLife;
in vec3 vColor;
in float vSize;

out vec4 FragColor;

void main() {
    // 圆形粒子
    vec2 coord = gl_PointCoord - 0.5;
    float dist = length(coord);
    
    if (dist > 0.5) discard;
    
    float alpha = (1.0 - dist * dist) * (1.0 - vLife);
    
    FragColor = vec4(vColor, alpha);
}
`;

// 扭曲效果顶点着色器
export const DISTORTION_VERTEX_SHADER = `
#version 300 es
precision highp float;

in vec3 aPosition;
in vec2 aTexCoord;

out vec2 vTexCoord;

void main() {
    vTexCoord = aTexCoord;
    gl_Position = vec4(aPosition, 1.0);
}
`;

// 扭曲效果片段着色器
export const DISTORTION_FRAGMENT_SHADER = `
#version 300 es
precision highp float

in vec2 vTexCoord;

uniform sampler2D uTexture;
uniform float uTime;
uniform float uStrength;
uniform float uFrequency;

out vec4 FragColor;

// 正弦波扭曲
vec2 distort(vec2 uv, float time) {
    uv += sin(uv.x * uFrequency + time) * uStrength * 0.1;
    uv += sin(uv.y * uFrequency + time) * uStrength * 0.1;
    return uv;
}

void main() {
    vec2 distortedUV = distort(vTexCoord, uTime);
    
    // 防止超出边界
    distortedUV = clamp(distortedUV, 0.0, 1.0);
    
    FragColor = texture(uTexture, distortedUV);
}
`;

export default {
  BLACKHOLE_VERTEX_SHADER,
  BLACKHOLE_FRAGMENT_SHADER,
  PARTICLE_VERTEX_SHADER,
  PARTICLE_FRAGMENT_SHADER,
  DISTORTION_VERTEX_SHADER,
  DISTORTION_FRAGMENT_SHADER,
};
