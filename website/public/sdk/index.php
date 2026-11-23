<?php
declare(strict_types=1);
require dirname(__DIR__, 2) . '/lib/releases.php';
require dirname(__DIR__, 2) . '/lib/layout.php';

$exampleVm = <<<'CODE'
.intel_syntax noprefix
# NovaProtect SDK VM example: a hand-written block that fully virtualizes.
# Any body size works (the trampoline lives in its own arena; the region only
# needs a 5-byte jump), so even tiny thunks protect.
.text
.globl np_sdk_vm_demo
np_sdk_vm_demo:
    mov  r8, rcx
    .byte 0x48,0x8D,0x0D,0x00,0x00,0x00,0x00   # NOVAPROTECT_BEGIN marker
    .rept 20
    nop
    .endr
    mov  rax, r8
    mov  rcx, rdx
    add  rax, rcx
    xor  rax, rcx
    add  rax, 0x1234
    shl  rax, 3
    sub  rax, rcx
    or   rax, rcx
    and  rax, 0x00FFFF00
    inc  rax
    dec  rax
    not  rax
    neg  rax
    lea  rax, [rax+0x40]
    add  rax, rcx
    xor  rax, r8
    sub  rax, 0x77
    shl  rax, 5
    shr  rax, 2
    or   rax, 0x0101
    and  rax, 0x7FFFFFFF
    add  rax, rcx
    xor  rax, rdx
    not  rax
    neg  rax
    add  rax, 0x1111
    sub  rax, 0x2222
    shl  rax, 1
    or   rax, r8
    and  rax, 0x0F0F0F0F
    inc  rax
    xor  rax, rcx
    add  rax, rdx
    lea  rax, [rax+0x100]
    sub  rax, 0x33
    shr  rax, 4
    or   rax, 0x2020
    and  rax, 0x00FF00FF
    add  rax, r8
    xor  rax, rdx
    inc  rax
    dec  rax
    not  rax
    neg  rax
    add  rax, 0x7
    sub  rax, 0x9
    shl  rax, 2
    or   rax, rcx
    and  rax, 0x0000FFFF
    add  rax, rdx
    xor  rax, r8
    .rept 20
    nop
    .endr                                       # NOVAPROTECT_END marker
    ret
CODE;

$exampleDriver = <<<'CODE'
// Driver for the VM example. Build:
//   gcc -O2 example_driver.c example_vm.S -o sdk_vm_example.exe
#include <stdio.h>
#include <stdint.h>

extern uint64_t np_sdk_vm_demo(uint64_t a, uint64_t b);

int main(void)
{
    uint64_t got = np_sdk_vm_demo(0x1122334455667788ull, 0x8877665544332211ull);
    printf("sdk_vm_demo=%016llX\n", (unsigned long long)got);
    return 0;
}
CODE;

$apiRows = [
    ['<code class="inline">NOVAPROTECT_BEGIN("name")</code>', '在函数体内标记区域起点。x64 发出 <code class="inline">LEA RCX,[rip+0]</code> + 20 字节 NOP；x86 发出 <code class="inline">LEA ECX,[0]</code> + 20 字节 NOP。name 参数仅用于可读性，字节模式与名称无关。'],
    ['<code class="inline">NOVAPROTECT_END()</code>', '标记区域终点，20 字节 NOP。'],
    ['<code class="inline">NOVAPACK_BEGIN / NOVAPACK_END</code>', '旧版别名，生成完全相同的字节，既有工程无需修改。'],
    ['<code class="inline">NOVAPROTECT_SDK_VERSION</code>', '当前头文件版本字符串（如 <code class="inline">"2.2.7"</code>），可用于条件编译。'],
    ['<code class="inline">NOVAPROTECT_INLINE</code>', '编译器相关的内联属性宏（MSVC <code class="inline">__forceinline</code> / GCC <code class="inline">always_inline</code>）。'],
];

ob_start();
?>
<div class="page-head">
    <div class="row">
        <div>
            <span class="eyebrow">NovaProtect SDK</span>
            <h1><?= np_e(np_t('SDK 文档')) ?></h1>
            <p class="lede"><?= np_e(np_t('在应用源码里标记需要虚拟化或混淆的函数，再用 NovaProtect 客户端打包，标记区域即被降级为 VM 字节码。未保护版本里标记是完全无副作用的 NOP。')) ?></p>
        </div>
        <a class="button button-primary" href="/download/"><?= np_e(np_t('下载客户端')) ?></a>
    </div>
</div>

<div class="shell prose" style="padding-bottom:60px;">

    <section class="glass card card-pad-lg" id="quickstart" style="margin-top:28px;">
        <h2 style="margin-top:0;"><?= np_e(np_t('快速开始')) ?></h2>
        <ol>
            <li><?= np_t('把 <code class="inline">sdk/include/novaprotect_sdk.h</code> 放进你的工程。') ?></li>
            <li><?= np_t('用 <code class="inline">NOVAPROTECT_BEGIN("名称")</code> 和 <code class="inline">NOVAPROTECT_END()</code> 包住一个函数体。') ?></li>
            <li><?= np_e(np_t('正常编译出 EXE——标记在未保护版本里是无副作用的 NOP。')) ?></li>
            <li><?= np_e(np_t('在 NovaProtect 客户端选择该 EXE，模式设为虚拟化或 Ultra，开始保护。')) ?></li>
            <li><?= np_e(np_t('客户端扫描 BEGIN/END 字节边界、在对象编辑器列出每个区域，并把可翻译区域降级为 VM 字节码。')) ?></li>
        </ol>
    </section>

    <section class="glass card card-pad-lg" id="api">
        <h2 style="margin-top:0;"><?= np_e(np_t('API 参考')) ?></h2>
        <p><?= np_t('头文件 <code class="inline">novaprotect_sdk.h</code> 提供以下宏；只依赖编译器内联汇编，无运行时库、无 DLL。') ?></p>
        <div class="table-wrap">
            <table class="data">
                <thead><tr><th><?= np_e(np_t('宏')) ?></th><th><?= np_e(np_t('说明')) ?></th></tr></thead>
                <tbody>
                    <?php foreach ($apiRows as [$macro, $desc]): ?>
                    <tr><td><?= np_t($macro) ?></td><td><?= np_t($desc) ?></td></tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <h3><?= np_e(np_t('字节模式与编译器')) ?></h3>
        <ul>
            <li><?= np_t('要求 <strong>x86 或 x64 Windows</strong> 目标（<code class="inline">_WIN32</code> / <code class="inline">_WIN64</code>），否则预处理报错。') ?></li>
            <li><?= np_t('标记通过 <code class="inline">__asm__ volatile</code>（GCC / Clang 风格内联汇编）发出；MSVC 下使用其兼容路径。') ?></li>
            <li><?= np_t('检测器扫描的是<strong>固定字节序列</strong>，与宏的 name 参数无关——同一函数内不要嵌套重复标记。') ?></li>
            <li><?= np_t('标记是位置无关的 <code class="inline">LEA</code> + NOP 滑条，不引用全局符号，链接与剥离均不受影响。') ?></li>
        </ul>
    </section>

    <section class="glass card card-pad-lg" id="example">
        <h2 style="margin-top:0;"><?= np_e(np_t('标记示例')) ?></h2>
        <p><?= np_t('普通函数体打标记（完整示例见仓库 <code class="inline">sdk/examples/example.cpp</code>）：') ?></p>
<pre class="code"><span class="cm"><?= htmlspecialchars('// secret_calc 被标记为 VM 区域；-O0 编译保持体足够简单', ENT_QUOTES) ?></span>
#include "novaprotect_sdk.h"

int secret_calc(int x)
{
    NOVAPROTECT_BEGIN("secret_calc");
    int a = x + 3;
    int b = x - 7;
    int c = a ^ b;
    c = c * 0x9E3779B9 + a;
    NOVAPROTECT_END();
    return c;
}</pre>
        <p><?= np_t('建议用 <code class="inline">-O0</code> 或 volatile 局部变量编译标记文件，避免优化器把标记区与周边代码合并。') ?></p>
    </section>

    <section class="glass card card-pad-lg" id="scanner">
        <h2 style="margin-top:0;"><?= np_e(np_t('手动添加函数保护（无需改源码）')) ?></h2>
        <p><?= np_t('除 SDK 标记外，客户端「保护」页内置 <strong>VMP 式函数扫描器</strong>：') ?></p>
        <ul>
            <li><?= np_t('对 x64 目标读取 <code class="inline">.pdata</code> 异常目录，枚举全部运行时函数（含静态函数），按 RVA 排序。') ?></li>
            <li><?= np_e(np_t('列表显示名称 / 地址 / 节 / 大小 / 模式 / 可虚拟化性；支持过滤与逐个勾选。')) ?></li>
            <li><?= np_e(np_t('「添加所有函数」一键全选；批量设置模式（继承 / 虚拟化 / Ultra / 仅前置变异 / 跳过）、VM 复杂度、变异强度与激活锁定。')) ?></li>
            <li><?= np_t('扫描出来的函数按<strong>完整函数区间</strong>虚拟化：帧序言与尾声/RET 同样进 VM（push/leave/ret 全降低），多返回、共享尾声、尾调用全部正确；降不了的指令形式经原生桥执行。') ?></li>
        </ul>
    </section>

    <section class="glass card card-pad-lg" id="constraints">
        <h2 style="margin-top:0;"><?= np_e(np_t('完整虚拟化的约束')) ?></h2>
        <p><?= np_t('翻译器把 x86-64 翻译成 wire 指令集（145 个操作码）交给随镜像分发的解释器执行。同一目标 5266 个函数实测，5351 个 chunk <strong>全部可虚拟化、零拒绝桶</strong>，<strong>100.0% 的函数字节被虚拟化</strong>（1,589,043 / 1,589,307）。已覆盖：') ?></p>
        <ul>
            <li><?= np_t('整数 ALU <strong>8/16/32/64 位全宽度</strong>，标志在操作数宽度上精确计算（<code class="inline">add al,bl</code> 之后的 <code class="inline">jb</code> 读到的是字节进位）；') ?></li>
            <li><?= np_t('移位/旋转全宽度（含 SHLD/SHRD）、MOV/MOVZX/MOVSX/LEA（含 SIB 比例变址、无基址、RIP 相对）、XCHG/XADD/PUSH/POP（帧序言与尾声同样进 VM）、<code class="inline">moffs</code> 绝对寻址；') ?></li>
            <li><?= np_t('全部条件跳转、直接/间接 JMP 与 CALL、RET（降低为间接出口）与尾调用、SETcc/CMOVcc；') ?></li>
            <li><?= np_e(np_t('SSE 算术与浮点：加减乘除/开方/min/max × 标量与打包、位运算、全部比较谓词、16 种数据类型转换；')) ?></li>
            <li><?= np_t('整数 SIMD、SSE 数据移动、位测试族（BT/BTS/BTR/BTC、BSF/BSR）、x87 浮点、字符串指令（含方向标志 DF）、CMPXCHG（内存形态含 LOCK）、CPUID/RDTSC/RDRAND、UD2、<code class="inline">enter</code>/<code class="inline">pushfq</code>/<code class="inline">popfq</code>、8 位乘除对、标志传送（SAHF/LAHF/STC/CLC/CMC/CLD/STD）、128 位乘除、CDQ/CQO。') ?></li>
        </ul>
        <p><?= np_t('以下形态经<strong>原生桥</strong>执行——chunk 在该指令前停止、指令按原生语义在两个 VM 区之间运行、随后继续开新 chunk，函数其余部分照常虚拟化（实测目标中零出现）：') ?></p>
        <ul>
            <li><?= np_t('AVX/VEX/EVEX 前缀指令（长度已精确解码，桥切分位置准确）、16 位 <code class="inline">push</code>/<code class="inline">pop</code>、<code class="inline">enter</code> 嵌套帧；') ?></li>
            <li><?= np_t('<code class="inline">cmpxchg8b/16b</code> 与寄存器-寄存器 <code class="inline">cmpxchg</code>（原子原语——任何 VM 合成都会丢跨线程原子性，必须原生执行）。') ?></li>
        </ul>
        <p><?= np_t('深度不可界定的栈深（<code class="inline">sub rsp, reg</code>，即 <code class="inline">__chkstk</code>/alloca 形态）同样经<strong>原生桥</strong>切分：该指令原生执行于两个 VM chunk 之间，前后区域继续虚拟化。') ?></p>
        <p><?= np_t('跳过原因在构建日志里<strong>按类计数</strong>打印（<code class="inline">VM skip summary</code>），不是静默丢弃。') ?></p>
        <div class="notice">
            <?= np_t('<strong>体积下限：</strong>运行时 trampoline 需要约 <code class="inline">51 + 10 × 保留寄存器数 + 16</code> 字节；解释器参数与调用约定固定保留 rax/rcx/rdx/r8–r11，区域头部只写一个 5 字节 <code class="inline">jmp rel32</code>，trampoline 本体生成到独立的可执行 arena（每区域预留 1024 字节），所以<strong>最小可虚拟化区域是 5 字节</strong>。早期版本要求区域容纳完整 trampoline（约 137 字节），现在没有这个限制。') ?>
        </div>
        <p><?= np_t('区域表上限 <strong>8192</strong>（2.3.20 起放开）：这只是损坏计数的防护上限，每个描述符仍按自身区域大小做边界检查。') ?></p>
        <p><?= np_e(np_t('关键函数直接标记或函数扫描即可完整虚拟化（含栈帧与内存访问）；手写汇编块（见下例）是体积最小、字节码最紧凑的形态，任何尺寸都能保护。')) ?></p>
    </section>

    <section class="glass card card-pad-lg" id="assembly">
        <h2 style="margin-top:0;"><?= np_e(np_t('寄存器直通汇编示例')) ?></h2>
        <p><?= np_t('<code class="inline">sdk/examples/example_vm.S</code>——可真正虚拟化的寄存器直线型块（节选结构，完整文件见仓库）：') ?></p>
<pre class="code"><?= htmlspecialchars($exampleVm, ENT_QUOTES) ?></pre>
        <p><?= np_t('配套驱动 <code class="inline">sdk/examples/example_driver.c</code>，用于验证保护前后结果一致：') ?></p>
<pre class="code"><?= htmlspecialchars($exampleDriver, ENT_QUOTES) ?></pre>
        <p><?= np_e(np_t('构建：')) ?></p>
<pre class="code">gcc -O2 example_driver.c example_vm.S -o sdk_vm_example.exe</pre>
    </section>

    <section class="glass card card-pad-lg" id="runtime">
        <h2 style="margin-top:0;"><?= np_e(np_t('反沙箱 / 反转储 / 环境自检')) ?></h2>
        <p><?= np_t('打包时可在客户端独立开启三项运行时防护（详见<a href="/features/#runtime">功能详解</a>）：') ?></p>
        <ul>
            <li><?= np_t('<strong>反沙箱检测</strong>：累计评分 CPU 数、物理内存、已知沙箱模块与监控组件、RDTSCP 时序、CPU 核掩码、睡眠压缩与桌面/用户名模板，超过阈值即终止。') ?></li>
            <li><?= np_t('<strong>反内存转储</strong>：校验 MZ/PE 头、区段表与 PEB 加载基址，拦截 Procdump/Minidump 后处理。') ?></li>
            <li><?= np_t('<strong>交互桌面环境自检</strong>：校验 CPU 数、内存、开机时长、屏幕分辨率、显示器数。') ?></li>
        </ul>
        <p><?= np_e(np_t('这些只对原生 x64 生效，且默认关闭，按需开启避免误杀。')) ?></p>
    </section>

    <section class="glass card card-pad-lg" id="vmprotect">
        <h2 style="margin-top:0;"><?= np_e(np_t('与商业 VMProtect 的关系')) ?></h2>
        <p><?= np_t('客户端自身与 NovaProtect 核心运行时使用商业 VMProtect SDK 做启动级虚拟化与防篡改（构建时自动链接 <code class="inline">VMProtectSDK64.a</code>，发布时附带 <code class="inline">VMProtectSDK64.dll</code>）。这是对 NovaProtect 自有 VM 引擎的补充——SDK 标记的区域由自有 wire VM 执行，两层互不替代。') ?></p>
    </section>

    <section class="glass card card-pad-lg" id="compat">
        <h2 style="margin-top:0;"><?= np_e(np_t('兼容性')) ?></h2>
        <ul>
            <li><?= np_t('旧版 <code class="inline">NOVAPACK_BEGIN</code> / <code class="inline">NOVAPACK_END</code> 继续可用，字节模式不变。') ?></li>
            <li><?= np_t('x86 与 x64 都支持 marker 扫描；<strong>VM 翻译仅 x64</strong>。') ?></li>
            <li><?= np_e(np_t('标记区域在未保护构建中为 NOP，不改变控制流、不引入依赖，可直接随源码分发。')) ?></li>
            <li><?= np_t('客户端与 SDK 版本独立演进；以仓库 <code class="inline">sdk/README.md</code> 与本页为准。') ?></li>
        </ul>
        <div class="download-actions" style="margin-top:22px;">
            <a class="button button-primary" href="/download/"><?= np_e(np_t('下载客户端')) ?></a>
            <a class="button button-secondary" href="https://github.com/sudfiona/NovaProtect/tree/master/sdk" target="_blank" rel="noopener noreferrer"><?= np_e(np_t('SDK 源码')) ?></a>
            <a class="button button-secondary" href="/features/#functions"><?= np_e(np_t('函数保护详解')) ?></a>
        </div>
    </section>

</div>
<?php
$body = ob_get_clean();
np_layout(
    np_t('SDK 文档'),
    'sdk',
    $body,
    np_t('NovaProtect SDK 文档：NOVAPROTECT_BEGIN/END 标记用法、字节模式、VM 约束、汇编示例与兼容性说明。')
);
