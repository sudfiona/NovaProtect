<?php
declare(strict_types=1);

/**
 * Bilingual shell for the marketing site.
 *
 * Chinese source text is the lookup key rather than an invented symbolic one:
 *
 *  - page markup stays readable in its own wording, so a translator can diff
 *    template against dictionary without a key registry;
 *  - a missing English entry falls back to correct Chinese instead of a blank
 *    label or a raw key leaking into the page, so a half-finished dictionary
 *    can still ship;
 *  - repeated copy ("下载客户端" appears on six pages) is translated once.
 *
 * Resolution order: ?lang= query (and then remembered), np-lang cookie,
 * Accept-Language, default zh. The query wins so a shared ?lang=en link is not
 * overridden by whatever the visitor picked last time.
 */

const NP_LANG_COOKIE = 'np-lang';
const NP_LANG_DEFAULT = 'zh';
const NP_LANGS = ['zh', 'en'];

/** Resolved UI language, decided once per request. */
function np_lang(): string
{
    static $resolved = null;
    if ($resolved !== null) {
        return $resolved;
    }

    $picked = null;
    $explicit = false;

    // 1. Explicit switch. Remember it, then drop it from later link building so
    //    the cookie carries the choice.
    if (isset($_GET['lang']) && is_string($_GET['lang'])) {
        $query = strtolower(trim($_GET['lang']));
        if (in_array($query, NP_LANGS, true)) {
            $picked = $query;
            $explicit = true;
        }
    }

    // 2. Cookie from an earlier switch.
    if ($picked === null && isset($_COOKIE[NP_LANG_COOKIE]) && is_string($_COOKIE[NP_LANG_COOKIE])) {
        $cookie = strtolower(trim($_COOKIE[NP_LANG_COOKIE]));
        if (in_array($cookie, NP_LANGS, true)) {
            $picked = $cookie;
        }
    }

    // 3. Browser preference — first supported primary subtag wins.
    if ($picked === null && isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) && is_string($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
        foreach (explode(',', $_SERVER['HTTP_ACCEPT_LANGUAGE']) as $range) {
            $primary = strtolower(substr(trim(explode(';', $range)[0]), 0, 2));
            if (in_array($primary, NP_LANGS, true)) {
                $picked = $primary;
                break;
            }
        }
    }

    $resolved = $picked ?? NP_LANG_DEFAULT;

    // Persist only an explicit choice. Remembering a language that was merely
    // guessed from Accept-Language would set a cookie nobody asked for, and the
    // privacy page promises not to.
    if ($explicit && !headers_sent()) {
        setcookie(NP_LANG_COOKIE, $resolved, [
            'expires' => time() + 31536000,
            'path' => '/',
            'samesite' => 'Lax',
        ]);
    }

    return $resolved;
}

function np_is_en(): bool
{
    return np_lang() === 'en';
}

/** Value for the <html lang> attribute. */
function np_html_lang(): string
{
    return np_is_en() ? 'en' : 'zh-CN';
}

/**
 * Translate one source string. Unknown strings come back unchanged, which keeps
 * an incomplete dictionary readable instead of blanking the page.
 */
function np_t(string $zh): string
{
    if (np_lang() === 'zh') {
        return $zh;
    }

    static $dict = null;
    if ($dict === null) {
        /** @var array<string, string> $loaded */
        $loaded = require __DIR__ . '/i18n-en.php';
        $dict = $loaded;
    }

    return $dict[$zh] ?? $zh;
}

/**
 * href that switches the current page to another language.
 *
 * The request path is attacker-controlled, so it is constrained to a plain
 * absolute path: without that a crafted URI such as //evil.example/ would turn
 * the switcher into a protocol-relative redirect.
 */
function np_lang_href(string $lang): string
{
    $lang = in_array($lang, NP_LANGS, true) ? $lang : NP_LANG_DEFAULT;

    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    if (!is_string($path) || $path === '' || $path[0] !== '/'
        || preg_match('#^/[A-Za-z0-9/._~%\-]*$#', $path) !== 1) {
        $path = '/';
    }

    $query = $_GET;
    $query['lang'] = $lang;

    return $path . '?' . http_build_query($query);
}

/** Language chips, styled like the theme chips.
 *
 * Anchor instead of button: switching language is a navigation, so the links
 * survive middle-click, get crawled per-language and need no JavaScript.
 */
function np_lang_switch(): string
{
    $current = np_lang();
    $labels = ['zh' => np_t('中文'), 'en' => np_t('英文')];

    $out = '<div class="lang-switch" role="group" aria-label="' . np_e(np_t('界面语言')) . '">';
    foreach (NP_LANGS as $lang) {
        $isCurrent = $lang === $current;
        $out .= '<a class="theme-btn" href="' . np_e(np_lang_href($lang)) . '"'
            . ($isCurrent ? ' aria-current="true"' : '')
            . ' hreflang="' . $lang . '"'
            . ' title="' . np_e($labels[$lang]) . '">'
            . np_e($lang === 'en' ? 'EN' : '中')
            . '</a>';
    }
    return $out . '</div>';
}
