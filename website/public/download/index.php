<?php
declare(strict_types=1);
require dirname(__DIR__, 2) . '/lib/releases.php';
require dirname(__DIR__, 2) . '/lib/layout.php';

$latest = np_latest_release();
$asset = $latest !== null ? np_release_asset($latest) : null;
$recent = array_slice(np_releases(), 1, 5);
$repo = 'https://github.com/sudfiona/NovaProtect';

ob_start();
?>
<div class="page-head">
    <span class="eyebrow">NovaProtect releases</span>
    <h1>下载 NovaProtect</h1>
    <p class="lede">Windows x64 客户端，无需账户即可下载。安装包发布在 GitHub Releases，本站不托管二进制文件；版本信息自动同步自 GitHub。</p>
</div>

<div class="shell">
    <?php if ($latest !== null && $asset !== null): ?>
    <div class="download-hero">
        <div class="glass download-card">
            <div class="version-line">
                <strong>v<?= np_e($latest['version']) ?></strong>
                <span class="pill <?= $latest['prerelease'] ? 'pill-muted' : 'pill-success' ?>">
                    <?= $latest['prerelease'] ? '预发布' : '正式版' ?>
                </span>
                <?php if ($latest['publishedAt'] !== ''): ?>
                <time class="text-muted" datetime="<?= np_e($latest['publishedAt']) ?>"><?= np_e($latest['publishedAt']) ?> 发布</time>
                <?php endif; ?>
            </div>
            <p class="file-line"><?= np_e($asset['name']) ?> · Windows x64 · <?= np_e(np_format_bytes($asset['size'])) ?></p>
            <?php if ($asset['sha256'] !== ''): ?>
            <div class="sha-line">SHA-256 <?= np_e($asset['sha256']) ?></div>
            <?php endif; ?>
            <div class="download-actions">
                <a class="button button-primary button-large" href="<?= np_e($asset['url']) ?>">下载安装包</a>
                <a class="button button-secondary button-large" href="<?= np_e($latest['pageUrl'] !== '' ? $latest['pageUrl'] : $repo . '/releases/latest') ?>" target="_blank" rel="noopener noreferrer">在 GitHub 查看</a>
            </div>
            <?php if (trim($latest['notes']) !== ''): ?>
            <div class="notice" style="margin-bottom:0;">
                <?php $flat = trim(preg_replace('/\s+/', ' ', $latest['notes']) ?? $latest['notes']); ?>
                <strong>本次更新：</strong><?= np_e(np_truncate($flat, 240)) ?><?= strlen($flat) > 240 ? '…' : '' ?>
            </div>
            <?php endif; ?>
        </div>
        <div class="download-side">
            <div class="glass card">
                <h3>完整性与签名</h3>
                <p>每个版本的 SHA-256 摘要随 Release 附件发布，上方校验值取自 GitHub 提供的素材摘要。客户端更新器下载后逐字节校验，不一致就不会安装。</p>
                <p class="text-muted" style="margin-top:10px;">安装包未附带 Authenticode 签名，Windows 可能提示未知发布者；请以哈希核对结果为准。</p>
            </div>
            <div class="glass card">
                <h3>客户端如何更新</h3>
                <p>桌面客户端直接向 GitHub 检查更新并下载安装包，不经过本站。本站只是说明页面——没有后台、没有数据库。</p>
            </div>
        </div>
    </div>

    <?php if ($recent !== []): ?>
    <section class="section">
        <div class="section-head">
            <span class="eyebrow">Recent</span>
            <h2>近期版本</h2>
            <p>完整列表见<a href="/client-updates/">更新日志</a>。</p>
        </div>
        <div class="mini-list">
            <?php foreach ($recent as $release): $releaseAsset = np_release_asset($release); ?>
            <div class="mini-row">
                <span>
                    <strong>v<?= np_e($release['version']) ?></strong>
                    <?php if ($release['prerelease']): ?><span class="pill pill-muted" style="margin-left:8px;">预发布</span><?php endif; ?>
                </span>
                <time datetime="<?= np_e($release['publishedAt']) ?>"><?= np_e($release['publishedAt']) ?></time>
                <a class="button button-small button-ghost" href="<?= np_e($releaseAsset !== null ? $releaseAsset['url'] : ($release['pageUrl'] !== '' ? $release['pageUrl'] : $repo . '/releases')) ?>" target="_blank" rel="noopener noreferrer">下载 / 查看</a>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <?php else: ?>
    <div class="glass card empty-state">
        <h2>版本信息暂时不可用</h2>
        <p>无法读取 GitHub Releases。请稍后刷新，或直接访问 <a href="<?= np_e($repo . '/releases') ?>" target="_blank" rel="noopener noreferrer">GitHub Releases 页面</a>。</p>
    </div>
    <?php endif; ?>

    <section class="section">
        <div class="glass card">
            <h3 style="margin-top:0;">系统要求</h3>
            <ul style="margin:0;color:var(--ink-2);">
                <li>Windows 10 / 11 x64（安装包目标平台）</li>
                <li>被保护目标：C/C++、C#/VB .NET、Rust、Golang 生成的 x86/x64 EXE</li>
                <li>无需账户、无需联网即可使用保护功能；仅在线更新需要访问 GitHub</li>
            </ul>
        </div>
    </section>
</div>
<?php
$body = ob_get_clean();
np_layout('下载', 'download', $body, '下载 NovaProtect Windows x64 客户端。安装包发布在 GitHub Releases，附 SHA-256 摘要，版本自动同步。');
