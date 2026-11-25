#!/bin/bash
# NovaProtect 官网打包脚本（包含黑洞系统）
# 
# 使用方法:
#   bash package-website.sh [version]
#
# 示例:
#   bash package-website.sh 2.5.0

set -e

# 版本号（从命令行获取或使用默认值）
VERSION="${1:-2.5.0}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PACKAGE_NAME="NovaProtect-Website-${VERSION}-Integrated-${TIMESTAMP}"

# 路径定义
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEBSITE_DIR="${SCRIPT_DIR}/website"
PUBLIC_DIR="${WEBSITE_DIR}/public"
BUILD_DIR="${SCRIPT_DIR}/build"
PACKAGE_DIR="${BUILD_DIR}/${PACKAGE_NAME}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 日志函数
log() { echo -e "${BLUE}[*]${NC} $@"; }
success() { echo -e "${GREEN}[✓]${NC} $@"; }
error() { echo -e "${RED}[✗]${NC} $@"; exit 1; }
warn() { echo -e "${YELLOW}[!]${NC} $@"; }

# 清理和准备
log "清理旧包..."
rm -rf "${BUILD_DIR}"
mkdir -p "${PACKAGE_DIR}"

# 验证必要文件
log "验证必要文件..."
[ -d "${PUBLIC_DIR}" ] || error "官网目录不存在: ${PUBLIC_DIR}"
[ -d "${PUBLIC_DIR}/blackhole-system" ] || error "黑洞系统未集成: ${PUBLIC_DIR}/blackhole-system"
[ -f "${WEBSITE_DIR}/deploy/install.sh" ] || error "部署脚本未找到"

# 复制官网文件
log "复制官网文件..."
cp -r "${PUBLIC_DIR}" "${PACKAGE_DIR}/public"
success "✓ 官网文件已复制"

# 复制部署脚本
log "复制部署脚本..."
mkdir -p "${PACKAGE_DIR}/deploy"
cp -r "${WEBSITE_DIR}/deploy"/* "${PACKAGE_DIR}/deploy/"
success "✓ 部署脚本已复制"

# 创建版本文件
log "生成版本文件..."
cat > "${PACKAGE_DIR}/VERSION" << EOF
NovaProtect Website with Black Hole System
Version: ${VERSION}
Built: $(date "+%Y-%m-%d %H:%M:%S")
Package: ${PACKAGE_NAME}

Features:
  - WebGL 2.0 Black Hole System (120 FPS)
  - 50K+ Particle System
  - Full Interaction Support
  - Responsive Design
  - Automatic Theme Adaptation
  - Performance Optimization

Directories:
  public/              - Website files (document root)
  public/blackhole-system/  - Integrated black hole system
  deploy/              - Deployment scripts

Installation:
  1. bash deploy/install.sh --check-package    # Validate
  2. sudo bash deploy/install.sh                # Install

Documentation:
  - deploy/README.md                 - Deployment guide
  - public/blackhole-system/WEBSITE_INTEGRATION_COMPLETE.md
EOF
success "✓ 版本文件已生成"

# 创建完整性检查清单
log "生成文件清单..."
cd "${PACKAGE_DIR}"
find . -type f ! -name "SHA256SUMS" ! -name "*.sha256" | sort | while read file; do
  sha256sum "${file#./}"
done > SHA256SUMS
cd - > /dev/null
success "✓ SHA256 清单已生成 ($(wc -l < "${PACKAGE_DIR}/SHA256SUMS") 文件)"

# 创建包
log "生成安装包..."
cd "${BUILD_DIR}"
zip -r -q "${PACKAGE_NAME}.zip" "${PACKAGE_NAME}"
success "✓ 安装包已生成"

# 生成包的 SHA256
log "计算包的校验和..."
sha256sum "${PACKAGE_NAME}.zip" > "${PACKAGE_NAME}.zip.sha256"
success "✓ 校验和已生成"

# 生成部署说明
cat > "${BUILD_DIR}/${PACKAGE_NAME}-DEPLOYMENT.md" << 'DEPLOY_EOF'
# NovaProtect 官网部署说明（包含黑洞系统）

## 包内容

```
NovaProtect-Website-${VERSION}-Integrated-${TIMESTAMP}/
├── public/                                    # 官网文档根目录
│   ├── index.php
│   ├── css/
│   ├── js/
│   ├── blackhole-system/                    # ✅ 集成的黑洞系统
│   │   ├── bootstrap.js                     # 自动启动程序
│   │   ├── config/website-config.js         # 官网配置
│   │   ├── integration/website-integration.js
│   │   ├── core/
│   │   ├── particles/
│   │   └── ...
│   └── ...
├── deploy/                                   # 部署脚本
│   ├── install.sh                           # 主安装脚本
│   ├── nginx-location.conf
│   ├── health-check.sh
│   └── ...
├── VERSION                                   # 版本信息
└── SHA256SUMS                                # 文件清单

包大小: ~${PACKAGE_SIZE}
文件数: $(wc -l < SHA256SUMS) 个
```

## 快速部署

### Linux 服务器

```bash
# 1. 解压包
unzip NovaProtect-Website-*.zip -d novaprotect-site
cd novaprotect-site

# 2. 验证包完整性（可选）
bash deploy/install.sh --check-package

# 3. 安装
sudo bash deploy/install.sh

# 4. 验证
# 访问 http://your-domain/
# 切换主题查看黑洞系统效果
```

### 宝塔面板

```bash
# 1. 上传包到服务器
# 通过宝塔文件管理器上传 NovaProtect-Website-*.zip

# 2. 在终端执行
cd /path/to/uploaded/package
unzip NovaProtect-Website-*.zip -d novaprotect-site
cd novaprotect-site
sudo bash deploy/install.sh
```

## 验证部署

### 检查清单

- [ ] 官网正常访问 (http://your-domain/)
- [ ] 页面加载无 404 错误
- [ ] 黑洞主题可切换
- [ ] 粒子系统显示 (切换到黑洞主题)
- [ ] 浏览器控制台无 JavaScript 错误
- [ ] 性能正常 (FPS > 60)

### 测试黑洞系统

在浏览器控制台执行:

```javascript
// 查看黑洞实例
console.log(window.__novaprotect_blackhole);

// 获取统计信息
window.__novaprotect_blackhole.getStats();

// 切换主题测试
document.documentElement.dataset.theme = 'blackhole';
```

## 配置调整

编辑 `public/blackhole-system/config/website-config.js` 调整:

```javascript
// 增加粒子数（性能好的情况）
particles: { defaultCount: 50000 }

// 修改色系
colorPalette: [...]

// 调整光晕强度
lighting: { glowIntensity: 1.2 }
```

## 更新流程

```bash
# 1. 生成新包
bash package-website.sh 2.5.1

# 2. 验证包
bash deploy/install.sh --check-package

# 3. 执行升级 (会自动备份)
sudo bash deploy/upgrade.sh NovaProtect-Website-2.5.1-*.zip

# 4. 验证新版本
# 访问官网，查看版本号
```

## 故障排查

### 黑洞系统不显示

```bash
# 检查文件是否存在
ls -la public/blackhole-system/

# 检查权限
chmod -R 755 public/blackhole-system/

# 检查浏览器控制台错误
# 打开浏览器开发工具 (F12)，查看 Console 和 Network 标签
```

### 性能问题

1. 检查服务器 CPU/内存
2. 启用 Gzip 压缩
3. 启用浏览器缓存
4. 调整黑洞系统配置（见上面的配置调整）

## 文件完整性

包中的所有文件都在 `SHA256SUMS` 中列出并校验。

验证方法:

```bash
# 验证所有文件
cd /path/to/extracted/package
sha256sum -c SHA256SUMS

# 应输出: "OK" 对所有文件
```

## 相关文档

- [部署指南](deploy/README.md)
- [黑洞系统集成指南](public/blackhole-system/WEBSITE_INTEGRATION_COMPLETE.md)
- [API 参考](public/blackhole-system/API_REFERENCE.md)
- [官网集成指南](public/blackhole-system/WEBSITE_INTEGRATION.md)

## 技术支持

如遇问题:

1. 查看 `deploy/health-check.sh` 输出
2. 检查 Nginx 日志: `/www/server/*/log/`
3. 检查 PHP 日志（如有）
4. 阅读上面的故障排查部分

## 版本信息

版本: ${VERSION}
构建时间: $(date "+%Y-%m-%d %H:%M:%S")
黑洞系统: 1.0.0 (集成)
官网框架: Laravel-based Static

DEPLOY_EOF

success "✓ 部署说明已生成"

# 最终总结
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ 官网打包完成！${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "包信息："
echo "  名称: ${PACKAGE_NAME}"
echo "  路径: ${BUILD_DIR}/${PACKAGE_NAME}.zip"
echo "  大小: $(du -h "${BUILD_DIR}/${PACKAGE_NAME}.zip" | cut -f1)"
echo "  文件: $(wc -l < "${PACKAGE_DIR}/SHA256SUMS") 个"
echo "  校验: $(cat "${BUILD_DIR}/${PACKAGE_NAME}.zip.sha256")"
echo ""
echo "包含特性："
echo "  ✓ 官网完整文件"
echo "  ✓ 黑洞系统（120FPS, 50K+粒子）"
echo "  ✓ 自动启动程序"
echo "  ✓ 官网专用配置"
echo "  ✓ 部署脚本"
echo "  ✓ 完整文档"
echo ""
echo "下一步："
echo "  1. 上传到服务器: scp ${BUILD_DIR}/${PACKAGE_NAME}.zip user@server:/path/"
echo "  2. 验证: cd /path && bash ${PACKAGE_NAME}/deploy/install.sh --check-package"
echo "  3. 安装: sudo bash ${PACKAGE_NAME}/deploy/install.sh"
echo ""
echo "更多信息: ${BUILD_DIR}/${PACKAGE_NAME}-DEPLOYMENT.md"
echo ""
