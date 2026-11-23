<?php
declare(strict_types=1);
require dirname(__DIR__, 2) . '/lib/releases.php';
require dirname(__DIR__, 2) . '/lib/layout.php';

ob_start();
?>
<div class="page-head">
    <span class="eyebrow">Privacy</span>
    <h1><?= np_e(np_t('隐私说明')) ?></h1>
    <p class="lede"><?= np_e(np_t('NovaProtect 是纯静态说明页面，不收集访问数据、不做用户追踪；只有你主动切换界面语言时，才会写入一个记录语言选择的 Cookie。')) ?></p>
</div>

<div class="shell prose" style="padding-bottom:60px;">
    <section class="glass card card-pad-lg" style="margin-top:20px;">
        <p><?= np_t(' NovaProtect <strong>不提供</strong>用户账户、会员或邮件验证服务。本站没有后台、没有数据库，也不需要登录。') ?></p>
        <p><?= np_t('客户端下载指向 GitHub Releases，下载行为受 <a href="https://docs.github.com/site/github/getting-started-with-github/privacy-policies" target="_blank" rel="noopener noreferrer">GitHub 的隐私政策</a> 约束。') ?></p>
        <p><?= np_t('桌面客户端通过 HTTPS 直接连 GitHub 检查更新并下载安装包，<strong>不经过本站</strong>；更新时按 GitHub 提供的摘要逐字节校验安装包。') ?></p>
        <p><?= np_t('客户端在本机保存运行记录、规避设置与诊断日志（可在设置页打开对应目录），这些数据<strong>不会上传</strong>到任何服务器，也与本站无关。') ?></p>
        <p><?= np_t('界面语言 Cookie（<code class="inline">np-lang</code>）只保存 <code class="inline">zh</code> 或 <code class="inline">en</code> 两个值之一，用于记住你的语言选择，不含标识符、不含追踪信息，有效期一年，清除浏览器 Cookie 即可删除。') ?></p>
        <p class="text-muted mb-0"><?= np_t('本站服务端仅在页面渲染时读取 GitHub Releases 公开数据并做短时缓存（默认每五分钟同步一次），不记录访问者身份。') ?></p>
    </section>
</div>
<?php
$body = ob_get_clean();
np_layout(
    np_t('隐私说明'),
    'privacy',
    $body,
    np_t('NovaProtect 官网隐私说明：无账户、不收集访问数据；界面语言 Cookie 只记录语言选择，客户端更新直连 GitHub。')
);
