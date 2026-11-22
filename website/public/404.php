<?php
declare(strict_types=1);
require dirname(__DIR__) . '/lib/releases.php';
require dirname(__DIR__) . '/lib/layout.php';

http_response_code(404);

ob_start();
?>
<div class="error-page">
    <div class="glass card card-pad-lg" style="max-width:520px;">
        <div class="code-big">404</div>
        <h1>页面不存在</h1>
        <p>这个地址没有对应的内容。可以从首页重新开始。</p>
        <div class="download-actions" style="justify-content:center;">
            <a class="button button-primary" href="/">返回首页</a>
            <a class="button button-secondary" href="/download/">下载客户端</a>
        </div>
    </div>
</div>
<?php
$body = ob_get_clean();
np_layout('页面不存在', '', $body, '页面不存在。');
