<?php
declare(strict_types=1);

function np_e($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function np_asset(string $path): string
{
    return '/' . ltrim($path, '/');
}

function np_layout(string $title, string $body): string
{
    $admin = np_admin_session();
    $nav = $admin
        ? '<a href="/admin">管理后台</a><form method="post" action="/logout" class="nav-form"><input type="hidden" name="csrf" value="' . np_e(np_csrf_token()) . '"><button type="submit">退出</button></form>'
        : '<a class="nav-cta" href="/admin">管理后台</a>';

    $uri = np_e((string) ($_SERVER['REQUEST_URI'] ?? '/'));
    $safeTitle = np_e($title);
    $ver = rawurlencode(np_website_version());

    return '<!doctype html><html lang="zh-CN"><head>'
        . '<meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<meta name="description" content="NovaProtect Windows EXE protection">'
        . '<link rel="canonical" href="https://nova.fbi.plus' . $uri . '">'
        . '<link rel="stylesheet" href="/css/site.css">'
        . '<link rel="icon" href="/favicon.ico">'
        . '<title>' . $safeTitle . ' · NovaProtect</title></head><body>'
        . '<a class="skip-link" href="#main-content">跳转到主要内容</a>'
        . '<header class="site-header"><nav class="nav-shell" aria-label="主导航">'
        . '<a class="brand" href="/"><img src="/assets/novaprotect.png" alt=""><span>NovaProtect</span></a>'
        . '<div class="nav-links">'
        . '<a class="nav-download" href="/download">下载</a>'
        . '<a href="/client-updates">更新日志</a>'
        . '<a class="nav-github" href="https://github.com/sudfiona/NovaProtect" target="_blank" rel="noopener noreferrer" aria-label="GitHub" title="GitHub">GitHub</a>'
        . $nav
        . '</div></nav></header>'
        . '<div class="site-main" id="main-content" tabindex="-1">' . $body . '</div>'
        . '<footer class="site-footer"><div><span>NovaProtect</span><span>Windows EXE protection</span></div>'
        . '<div><a href="/privacy">隐私</a><a href="https://github.com/sudfiona/NovaProtect" target="_blank" rel="noopener noreferrer">GitHub</a><span>© 2026 NovaProtect</span></div></footer>'
        . '<script src="/js/upload-progress.js?v=' . $ver . '" defer></script></body></html>';
}

function np_page(string $title, string $body): void
{
    header('Content-Type: text/html; charset=utf-8');
    echo np_layout($title, $body);
    exit;
}

function np_error(string $message, int $status = 400): void
{
    http_response_code($status);
    np_page('错误',
        '<main class="auth-shell"><section class="auth-panel">'
        . '<div class="eyebrow">NovaProtect</div>'
        . '<h1>无法继续</h1>'
        . '<p class="form-error">' . np_e($message) . '</p>'
        . '<p><a class="button button-secondary" href="/">返回首页</a></p>'
        . '</section></main>');
}

function np_form_error(string $message): string
{
    return $message === '' ? '' : '<div class="form-error" role="alert">' . np_e($message) . '</div>';
}
