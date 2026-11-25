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
    <h1><?= np_e(np_t('下载 NovaProtect')) ?></h1>
    <p class="lede"><?= np_e(np_t('Windows x64 客户端，无需账户即可下载。安装包发布在 GitHub Releases，本站不托管二进制文件；版本信息每分钟自动同步一次。')) ?></p>
</div>

<div class="shell">
    <?php if ($latest !== null && $asset !== null): ?>
    <div class="download-hero">
        <div class="glass download-card">
            <div class="version-line">
                <strong>v<?= np_e(np_release_display_version($latest)) ?></strong>
                <span class="pill <?= $latest['prerelease'] ? 'pill-muted' : 'pill-success' ?>">
                    <?= np_e(np_t($latest['prerelease'] ? '预发布' : '正式版')) ?>
                </span>
                <?php if ($latest['publishedAt'] !== ''): ?>
                <time class="text-muted" datetime="<?= np_e($latest['publishedAt']) ?>"><?= np_e($latest['publishedAt']) ?> <?= np_e(np_t('发布')) ?></time>
                <?php endif; ?>
            </div>
            <p class="file-line"><?= np_e($asset['name']) ?> · Windows x64 · <?= np_e(np_format_bytes($asset['size'])) ?></p>
            <?php if ($asset['sha256'] !== ''): ?>
            <div class="sha-line">SHA-256 <?= np_e($asset['sha256']) ?></div>
            <?php endif; ?>
            <div class="download-actions">
                <a class="button button-primary button-large" href="<?= np_e($asset['url']) ?>"><?= np_e(np_t('下载安装包')) ?></a>
                <a class="button button-secondary button-large" href="<?= np_e($latest['pageUrl'] !== '' ? $latest['pageUrl'] : $repo . '/releases/latest') ?>" target="_blank" rel="noopener noreferrer"><?= np_e(np_t('在 GitHub 查看')) ?></a>
            </div>
            <?php if (trim($latest['notes']) !== ''): ?>
            <div class="notice" style="margin-bottom:0;">
                <?php $flat = trim(preg_replace('/\s+/', ' ', $latest['notes']) ?? $latest['notes']); ?>
                <?= np_t('<strong>本次更新：</strong>') ?><?= np_e(np_truncate($flat, 240)) ?><?= strlen($flat) > 240 ? '…' : '' ?>
            </div>
            <?php endif; ?>
        </div>
        <div class="download-side">
            <div class="glass card">
                <h3><?= np_e(np_t('完整性与签名')) ?></h3>
                <p><?= np_e(np_t('每个版本的 SHA-256 摘要随 Release 附件发布，上方校验值取自 GitHub 提供的素材摘要。客户端更新器下载后逐字节校验，不一致就不会安装。')) ?></p>
                <p class="text-muted" style="margin-top:10px;"><?= np_e(np_t('安装包未附带 Authenticode 签名，Windows 可能提示未知发布者；请以哈希核对结果为准。')) ?></p>
            </div>
            <div class="glass card">
                <h3><?= np_e(np_t('客户端如何更新')) ?></h3>
                <p><?= np_e(np_t('桌面客户端直接向 GitHub 检查更新并下载安装包，不经过本站。本站只是说明页面——没有后台、没有数据库。')) ?></p>
            </div>
        </div>
    </div>

    <?php if ($recent !== []): ?>
    <section class="section">
        <div class="section-head">
            <span class="eyebrow">Recent</span>
            <h2><?= np_e(np_t('近期版本')) ?></h2>
            <p><?= np_t('完整列表见<a href="/client-updates/">更新日志</a>。') ?></p>
        </div>
        <div class="mini-list">
            <?php foreach ($recent as $release): $releaseAsset = np_release_asset($release); ?>
            <div class="mini-row">
                <span>
                    <strong>v<?= np_e(np_release_display_version($release)) ?></strong>
                    <?php if ($release['prerelease']): ?><span class="pill pill-muted" style="margin-left:8px;"><?= np_e(np_t('预发布')) ?></span><?php endif; ?>
                </span>
                <time datetime="<?= np_e($release['publishedAt']) ?>"><?= np_e($release['publishedAt']) ?></time>
                <a class="button button-small button-ghost" href="<?= np_e($releaseAsset !== null ? $releaseAsset['url'] : ($release['pageUrl'] !== '' ? $release['pageUrl'] : $repo . '/releases')) ?>" target="_blank" rel="noopener noreferrer"><?= np_e(np_t('下载 / 查看')) ?></a>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <?php else: ?>
    <?php
    // The link markup stays out of the dictionary so the key is a stable
    // sentence with a %s slot instead of a string with a URL baked into it.
    $releasesLink = '<a href="' . np_e($repo . '/releases') . '" target="_blank" rel="noopener noreferrer">GitHub Releases</a>';
    ?>
    <div class="glass card empty-state">
        <h2><?= np_e(np_t('版本信息暂时不可用')) ?></h2>
        <p><?= str_replace('%s', $releasesLink, np_t('无法读取 GitHub Releases。请稍后刷新，或直接访问 %s 页面。')) ?></p>
    </div>
    <?php endif; ?>

    <section class="section">
        <div class="glass card">
            <h3 style="margin-top:0;"><?= np_e(np_t('系统要求')) ?></h3>
            <ul style="margin:0;color:var(--ink-2);">
                <li><?= np_e(np_t('Windows 10 / 11 x64（安装包目标平台）')) ?></li>
                <li><?= np_e(np_t('被保护目标：C/C++、C#/VB .NET、Rust、Golang 生成的 x86/x64 EXE')) ?></li>
                <li><?= np_e(np_t('无需账户、无需联网即可使用保护功能；仅在线更新需要访问 GitHub')) ?></li>
            </ul>
        </div>
    </section>
</div>
<?php
$body = ob_get_clean();
np_layout(
    np_t('下载'),
    'download',
    $body,
    np_t('下载 NovaProtect Windows x64 客户端。安装包发布在 GitHub Releases，附 SHA-256 摘要，每分钟自动同步 GitHub 版本。')
);
