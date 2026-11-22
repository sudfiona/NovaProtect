<?php
declare(strict_types=1);
require dirname(__DIR__, 2) . '/lib/releases.php';
require dirname(__DIR__, 2) . '/lib/layout.php';

$releases = np_releases();

ob_start();
?>
<div class="page-head">
    <div class="row">
        <div>
            <span class="eyebrow">NovaProtect client releases</span>
            <h1>客户端更新日志</h1>
            <p class="lede">客户端版本与更新说明直接取自 GitHub Releases，每五分钟自动同步一次——页面上出现的每个版本都是真实发布。</p>
        </div>
        <a class="button button-primary" href="/download/">下载客户端</a>
    </div>
</div>

<div class="shell" style="padding-bottom:70px;">
    <p class="text-muted" style="margin:18px 0 22px;">
        数据来源：<a href="https://github.com/sudfiona/NovaProtect/releases" target="_blank" rel="noopener noreferrer">sudfiona/NovaProtect Releases</a>
    </p>

    <?php if ($releases === []): ?>
    <div class="glass card empty-state">
        <h2>暂无更新记录</h2>
        <p>暂时无法读取 GitHub Releases，请稍后刷新或直接访问 <a href="https://github.com/sudfiona/NovaProtect/releases" target="_blank" rel="noopener noreferrer">GitHub</a>。</p>
    </div>
    <?php else: ?>
    <div class="release-list">
        <?php foreach ($releases as $release): $asset = np_release_asset($release); ?>
        <article class="glass release-card">
            <div class="release-meta">
                <span class="pill <?= $release['prerelease'] ? 'pill-muted' : 'pill-success' ?>">
                    <?= $release['prerelease'] ? '预发布' : '正式版' ?>
                </span>
                <span class="pill pill-soft">v<?= np_e($release['version']) ?></span>
                <?php if ($release['publishedAt'] !== ''): ?>
                <time datetime="<?= np_e($release['publishedAt']) ?>"><?= np_e($release['publishedAt']) ?></time>
                <?php endif; ?>
            </div>
            <h2>客户端 <?= np_e($release['version']) ?></h2>
            <div class="release-notes"><?= nl2br(np_e($release['notes'])) ?></div>
            <div class="release-foot">
                <?php if ($asset !== null): ?>
                <span><?= np_e($asset['name']) ?> · <?= np_e(np_format_bytes($asset['size'])) ?></span>
                <a class="button button-small button-ghost" href="<?= np_e($asset['url']) ?>">下载此版本</a>
                <?php endif; ?>
                <?php if ($release['pageUrl'] !== ''): ?>
                <a href="<?= np_e($release['pageUrl']) ?>" target="_blank" rel="noopener noreferrer">在 GitHub 查看 →</a>
                <?php endif; ?>
            </div>
        </article>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
</div>
<?php
$body = ob_get_clean();
np_layout('客户端更新日志', 'updates', $body, 'NovaProtect 客户端更新日志，每五分钟自动同步 GitHub Releases 版本与说明。');
