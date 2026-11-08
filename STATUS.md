# NovaProtect 项目状态

- **网站版本**：2.2.31
- **正式客户端版本**：2.3.33
- **主程序**：NovaProtect.exe
- **官网**：https://nova.fbi.plus
- **部署栈**：PHP 8.4 / PHP-FPM / Linux 宝塔 Nginx / CDNfly

## 已完成

1. 官网从 ASP.NET Core 迁移到 PHP，保留下载、更新日志、健康检查和浏览器安装向导。
2. `2.2.12` 移除账号/会员系统：没有用户注册、登录、邮箱验证、问题反馈或极验验证码；网站只保留匿名客户端下载、更新日志和一个管理员口令保护的后台（客户端发布上传、离线升级）。
3. 安装包支持 `bash install.sh` 一键部署、PHP-FPM socket 探测、Nginx 配置备份、发布槽位切换、SHA-256 校验和失败回滚。
4. 所有页面、API、下载和静态资源使用不缓存响应头。官网与客户端两个版本线独立推进：网站版本只由 `website/VERSION` 决定，客户端版本发布在 GitHub Releases。
5. 客户端和网站版本独立管理；网站版本为 2.2.26，客户端安装包版本为 2.3.18。
6. 对象编辑器、项目快照和架构能力矩阵继续以真实 NovaProtect SDK marker 和实际格式能力为准。
7. 管理后台支持离线升级 ZIP 上传、版本递增和 SHA-256/路径/入口校验；包暂存于 `/www/server/novaprotect/updates`，由 root 执行器自动复核、备份、迁移、健康检查并回滚。
8. 管理员口令在安装向导一次性设置，Argon2id（不可用时 PBKDF2-SHA256 60 万次）哈希保存；`/admin/login` 提供登录页，未登录访问 `/admin` 跳转登录页，登录有速率限制。
9. `2.2.13` 新增 SSH 管理员口令重置：`php /www/server/novaprotect/bin/reset-admin-password.php`（安装/升级自动部署，仅 root），支持交互、`--password`、`--stdin`、`--generate`；重置后旧口令立即失效、全部后台会话失效并清除登录限速，功能测试固化于 `tests/website_installer_test.py`。
10. `2.2.14` 修复 SSH 口令重置工具在已安装站点找不到 app 目录的问题：install.sh/upgrade.sh 把站点根写入 `/www/server/novaprotect/site-root`，工具按 `--app` → `NOVAPROTECT_APP_DIR` → 包内 app → site-root/current → state/current → `/www/wwwroot/nova.fbi.plus/current` → `/www/wwwroot/*/current|app` 顺序探测，新增 `--locate` 诊断模式，失败时给出排查命令；站点在 `/www/wwwroot/<域名>/current/app`，与 state 目录是两棵不同的树。
11. `2.2.12` 修复后台路由契约：登出后 `/admin` 302 跳转 `/admin/login`，`GET /admin/login` 返回登录页，`/client-updates` 更新日志页补上路由。
12. 资源区段加密时保留 `RT_ICON`/`RT_GROUP_ICON`：加密后文件在资源管理器中的图标与原文件逐字节一致（回归用例固化于 `tests/regress.ps1`）。
13. 客户端发布打包不再经过 VMProtect 后处理，直接正常打包；源码保留 VMProtect SDK marker 底子。上传 GitHub 的源码包由 `tools/package-github-source.ps1` 生成，排除构建产物与签名私钥。
14. `tools/package-client-release.ps1` 一键完成版本检查、全量构建、Inno Setup 安装包、`website/release.json` 元数据同步与本地 PHP 站点 E2E（匿名检查更新、下载、SHA-256 校验）；`tools/package-github-source.ps1` 生成 `NovaProtect-<版本>-source.zip`。
15. `2.3.1` 修复反沙箱拦截路径崩溃（prot64 blob 数据表绝对指针改定宽字符矩阵，build.ps1 增加构建期扫描断言）；全量重建后打包 `NovaProtect-Setup-2.3.1.exe`（58.1 MB，SHA-256 `6a4c457f…282e`），PHP E2E 72 项全过；官网同步升级 `2.2.16`，产出 Full/Upgrade 两个部署 ZIP。
17. `2.3.2` 新增手动函数保护（VMP 式函数扫描）：客户端「保护」页对 x64 目标读 `.pdata` 枚举全部运行时函数，支持勾选 / 全选 / 批量模式一键「添加所有函数」；引擎侧新增 `-func` 区域规格（FunctionSource=ScanFunction），函数级虚拟化只虚拟化到第一个 RET 之前、尾跳落在 RET 上由原生指令返回；区域表上限 64（与 runtime `np_vm_install` 一致）。同轮修复三个引擎级缺陷：REX.W 立即数符号扩展（变异 `add imm→sub -imm` 引入负立即数时 VM 算错）、x64 流 32 位操作数门禁（wire VM 为 64 位机，无法复现高 32 位清零与 32 位标志）、trampoline 调用者保存寄存器保留集（`rax/rcx/rdx/r8-r11` 会被解释器参数与 C ABI 破坏，编译器跨调用在这些寄存器里放活值即被踩）。E2E：变异强度 0-3 × 复杂度 6 全对；186 函数全保护（64 虚拟化 + 其余如实跳过）程序输出不变；回归 40 OK / 5 SKIP / 1 FAIL（缺 x86 fixture 的既定基线）。
16. 修复 PowerShell 5.1 无 BOM `.ps1` 按 GBK 读取导致 `installer/version.iss` 中文发布说明双重编码的问题（version.ps1 加 UTF-8 BOM）；安装包 PE 版本资源中文已验证正确，官网更新日志数据源无乱码。更新冒烟测试的强制更新 fixture 改为按当前版本动态生成，不再随版本升级过期。
18. `2.2.18` 后台客户端上传改为 WAF 安全的分片通道：浏览器把安装包切成 512 KB 分片，每片以 `NPCHUNK1:` 前缀 + base64 文本 POST 到 `/api/admin/release/{begin,chunk,finish,abort}`（单请求约 683 KB），报文里没有 multipart、没有文件名、没有 `.exe` 后缀、没有 PE 头，`NPCHUNK1:` 前缀保证首字节永远不会是 `MZ`，因此不触发 CDNfly 的文件上传规则和超大请求体规则；端点放在 `/api/` 前缀下，直接复用边缘策略里 origin pass-through + 全部挑战关闭的规则，不需要额外 WAF 白名单。分片失败自动重试 3 次，会话 6 小时过期并在下次 begin 时回收，鉴权用管理员会话 + `X-NovaProtect-Token` 头。同步把更新日志改成自动生成：从安装包 PE 版本资源的描述里读出摘要，按 `；` 拆成条目，加上版本/平台/体积表头，必要时可用 `client-release-notes.json` 按版本覆盖；`/admin` 的旧 multipart 通道保留为无 JS 回退。Nginx 对 `/api/` 放行 4 MB，`deploy/cdnfly-check.sh` 增加 `/api/admin/release/begin` 探测（401/400/422 视为边缘放行，403/444/challenge 视为被拦）。回归：`tests/client_release_chunked_upload_smoke.py`（118 分片、SHA-256、日志、报文特征、CSRF、缺片拒绝）与 `tests/client_release_upload_smoke.py` 全绿。

19. `2.2.19` 离线升级 ZIP 接入同一条 WAF 安全分片通道（`begin` 带 `kind=upgrade`，会话记住类型，`finish` 路由到升级发布器；`np_upload_upgrade_package` 拆成 wrapper + `np_publish_upgrade_package`，分片路径不携带文件名，ZIP 由 `ZipArchive::open` 自证格式）。同轮修掉两个让离线升级上传**从未成功过**的既有缺陷：① `np_upgrade_validate_archive` 把 `deploy/configure_nginx.py`、`deploy/nginx-location.conf` 列为禁止出现的"完整安装入口"，但 `deploy/upgrade.sh` 的必需文件清单和 `package-website.ps1` 的打包清单都要求这两个文件，三处矛盾导致任何合法升级包都被拒；② PowerShell 5.1 的 `ConvertTo-Json` 把单元素数组降级成字符串，包内 `package.json` 的 `entryPoints` 实际是 `"upgrade.sh"` 而非 `["upgrade.sh"]`，与 PHP 的 `!== ['upgrade.sh']` 严格比较永不相等。修复：禁止清单只保留 `install.sh`/`deploy/install.sh`/`deploy/entry-install.sh`；`package-website.ps1` 手工拼装 `package.json` 保证数组语义；PHP 侧同时容忍字符串与数组两种形状；`verify-website-package.ps1` 增加 `entryPoints` 未降级 + 取值匹配的回归断言。`tests/client_release_chunked_upload_smoke.py` 扩展出升级包分支（改写真实 2.2.19 升级包为 2.2.20 后上传：版本从包内 `VERSION` 读取、暂存目录已展开 `upgrade.sh`、请求不含 PE 头/ZIP 本地头、全部 <1MB）。

20. `2.2.20` 离线升级包去掉重复的客户端安装包：`package-website.ps1` 只为完整包生成 `downloads/`，升级包体积从 58.7 MB 降到 261 KB。升级时 `deploy/upgrade.sh` 改用服务器 `/www/server/novaprotect/downloads/` 里已有的那份安装包，并先按 `release.json` 的 SHA-256 校验；服务器上缺失或哈希不符会直接中止并提示改用完整包，不会带着错误状态继续。配套调整：`downloads/` 不再是升级包的必需目录；PHP 校验器把 `downloads/<clientFile>` 改为可选（带有时仍严格校验哈希）；`verify-website-package.ps1` 反向加断言——升级包里一旦出现 `downloads/*` 就报错，防止以后又被打回胖包；`upgrade.sh` 只在安装包确实随包携带时才执行 `install`，避免源和目标同一路径。测试：`tests/client_release_chunked_upload_smoke.py` 增加"精简升级包不含客户端安装包"断言，真实 261 KB 升级包整包上传通过。

21. `2.2.21` 修复后台上传报“请求方法不支持”：该页面来自 `np_error()` 的 HTML 分支，说明浏览器把 POST 发到了一个路由不认识的路径——典型成因是「新版 `upload-progress.js` + 旧版 `portal.php`」的混合部署，`fetch(null)` 会把请求解析成 `/null` 并得到 405。三层修复：① 前端 `endpoint()` 只接受以 `/api/` 开头的端点，任何端点缺失或非法就直接退回原生表单提交，绝不再把 null 交给 fetch；② `begin` 返回 404/405 时自动切换兼容上传并提示“网站包仍是旧版本”；③ 服务端 405 改为 JSON 并带上 `method`/`path`/`scheme`，同时写入 error_log。另新增只读诊断接口 `GET /api/admin/release/ping`（返回网站版本、收到的请求方法、协议、管理员状态、分片大小），`OPTIONS` 预检返回 204 而不是 405。`scheme` 为 `http` 即可确认是 http→https 的 301 把 POST 改写成了 GET。测试固化于 `tests/client_release_chunked_upload_smoke.py`（ping 返回 200 且版本正确、GET 打上传接口得到 405 且 body 含真实方法）。

22. `2.3.9` VM 引擎强化（对照 Themida/VMProtect 公开的设计参数实现，未引用其代码）：① **字节码执行期解码**。原来 `np_vm_install` 在加载时把整段字节码原地解密并常驻内存，任何时刻内存转储都能拿到完整 VM 程序；现在字节码全程保持密文，`np_vm_run` 通过 256 字节滑动窗口按需解码（计数器密钥流，第 i 字节只依赖 key/RVA/i>>3，因此向后跳转目标可随机访问）。副产品是 `VirtualProtect` 不再作用于该段，少了一个经典的断点落点。密钥与区域 RVA 紧跟在 256 字节反向表之后（`reverse+256` / `reverse+264`），`np_vm_run` 保持四参数 ABI，手写 trampoline 无需改动。授权校验程序走同一套。② **执行期反调试**：解释器每 4096 条指令重读 PEB `BeingDebugged`，命中则污染寄存器而不是明显中止（VMProtect "Ultra" 的做法）。③ 删除已无用的 RC4/分层解密与 `VirtualProtect` 字符串，运行时 blob 20000 → 19776 字节。新增 `np::vmBytecodeCrypt()`（`src/crypto_layers.cpp`）与运行时 `np_vm_window()` 必须逐字节一致，已用独立 C/C++ 对拍验证同一 key/RVA 输出相同。回归：2.3.8 基线 51 OK / 2 FAIL，2.3.9 同样 51 OK / 2 FAIL，零回归；`x64_vm`、`x64_vm_all`、`x64_lic_ok`、`x64_lic_bad`、`x64_vm_bad` 全通过。**遗留**：`x64_funcfile` / `x64_funcfile_bad` 两项在中文路径下失败，见第 23 条。

23. 修复命令行路径的中文编码缺陷（`x64_funcfile` / `x64_funcfile_bad` 两项回归失败）。根因：`wmain` 把宽字符参数转成 UTF-8 存入 `utf8Args`，但 `load_region_file()`（`-funcfile` / `-regionfile`）和 `load_script()`（`-script`）用窄 `std::ifstream(path)` 打开——Windows 下窄路径由 ANSI CRT 按活动代码页解码，GBK 系统上 UTF-8 字节无法匹配文件，于是报 `cannot open region file: ...澶栧寘椤圭洰...`（UTF-8 字节被当 GBK 显示）。修复：两处改用 `std::filesystem::u8path(path)` 显式走 UTF-8→UTF-16；顺带修掉同类的两个隐患——`PELib::load(const std::string&)` 窄重载同样改 `u8path`，`PELib::save()` 的临时文件名从 `target.string() + ".np.tmp"`（宽→ANSI→宽，非 GBK 字符会丢）改为直接拼宽路径。回归从 51 OK / 2 FAIL 变为 **53 OK / 0 FAIL**。

24. `2.3.10` 字节码优化器加入不透明谓词假跳转（Themida EnableFakeJumps），并修掉一个**既有的正确性缺陷**：原 `vmObfuscate` 的垃圾指令路径在每个原始指令前插入字节，却没有重算分支操作数里的绝对字节偏移，任何含分支的 VM 区域一旦开启复杂度就会被破坏（扁平化路径因为要求无分支才没暴露）。新的发射器把分支记录为「目标指令下标」的 fixup，布局确定后再回填真实偏移，并补上末尾哨兵 HALT。假跳转构造：`SHRI d,1; SHLI d,1; ANDI d,1`（任意 v 都得到 0）→ `CMPI d,0` → `JZ 后续`，随后是一段只碰死寄存器的不可达块，静态看是一条带条件的真实分支。插入点由标志位活跃性分析决定（分支是唯一的标志消费者），因此不会插在 `CMPI`/`TEST` 与其消费者之间。新增 `tests/vm_obfuscate_test.cpp`：三个夹具（循环/前向跳转/跨指令标志存活）× 5 个复杂度，用参考解释器验证语义并断言所有分支目标落在指令边界。

25. `2.3.10` 解释器拆分为乱序 handler 表（Themida RelocateHandlers）：44 个操作码各自成为独立的 `static` 处理函数，通过 `np_handlers[]` 间接调用，`switch` 被移除，单一断点不再覆盖全部指令语义，「找大 switch」的启发式也失去锚点。**关键约束**：保护 blob 是被逐字节复制进目标镜像的，静态初始化的函数指针数组会保留链接期地址、复制后指向无效内存，因此表在首次运行时由 `np_vm_init_handlers()` 填充（编译器对这些赋值生成 RIP 相对取址，复制后依然正确）。未知操作码保持原有语义（停止执行）而不是空转。运行时 blob 19776 → 22432 字节，bss +544（64 项 handler 表）。回归 53 OK / 0 FAIL。

26. `2.3.10` **EnableRevirtualization 已实装**（本条原为"未实现"，现更新）。融合 Themida 的阶段/微寄存器模型与 VMProtect 的扩展指令集与分段密钥，形成两层执行结构：
    - **外层阶段流**：`vmSplitStages` 在指令边界切分（绝不切断任何分支的两端），每段独立 256 字节操作码置换 + 独立密钥 + 独立 RVA 盐，段末尾 `WIRE_STAGEEND` 交棒；`np_vm_run_stream` 按 stageTable 推进。
    - **二级解释器**：`vmLiftGuestBlocks` 把每段中的直线算术 run（≥3 条、无内存/分支/嵌套）提升为 guest 块，交给独立的 `np_vm_guest` + `np_ghandlers` 分派执行；每块自带 16 字节寄存器置换（**全 16 槽双射**）与写回白名单 `writeMask`，标志位与所属阶段共享（块边界是打包器引入的，原程序没有）。
    - **指令集**：逻辑操作码 45 → 82，新增内存微操作、`rol/ror`、32 位形式、`movzx/movsx/movd`。`include/wire_table.h` 成为唯一真源，取代原先散在三处的长度/分支/标志判定副本。
    - **兼容性**：`np_vm_run` 保持四参数 ABI（trampoline 字节预算是硬约束），新增状态全部走 `reverse` 表尾部（+268 flags / +272 stageDelta / +276 guestDelta / +280 guestCount），全 0 即旧格式，无版本分支。开关 `-revirt` / `-revirt-level 0..4`，默认开启；失败即退化为单阶段，不影响可执行性。
    - **验证**：`tests/vm_revirt_test.cpp` 58 项断言全通过（含"提升后寄存器文件与参考解释器逐寄存器相等"，以及 level 1..4 的嵌套分派等价）；`tests/vm_target.exe` 打包后 `VM-OK`，12 个随机种子 12/12 通过；`-norevirtualization` 仍 `VM-OK`；`tests/regress.ps1` → **ALL PASS**。设计文档见 `docs/engine-redesign.md`，诊断工具 `tools/rtinspect.cpp`。
    - **本轮同时修复的既有缺陷**：`np_ghandlers` 建表后从未填充（guest 分派全部落空）；`npPatch32` 被当作追加函数使用会静默不写（trailer 全 0）；阶段/guest 表项误存 payload 绝对偏移（应从区域 reverse 表基址算，导致阶段 1 起全错）；`regPerm` 只对被触及寄存器做置换、其余塌缩到槽 0（寄存器互相覆盖，症状为 `got=0x1`）。另修 `build.ps1` / `build-regression-core.ps1` / `tests/regress.ps1` 在非 ASCII 路径下把绝对路径传给子编译器会被 OEM 代码页重新编码、导致 ld 报 `cannot find <乱码>.a` 的问题（改用相对路径）。
    - **`2.3.11` 多层嵌套实装**：`revirtualization_level` 不再只是意图回显，level 1..4 是真实嵌套层数——`vmRevirtualize` 把层 N-1 的 guest 块当作载体继续提升，运行时 `np_vm_guest` 遇到块内 `WIRE_GSTAGE` 递归进入下一层（深度上限 `NP_VM_GUEST_DEPTH=8`）。层级只写在描述符 `flags` 的 24..27 位（bit0 live / 8..23 writeMask / 24..27 level），整棵树仍是一张扁平索引表，运行时不需要每层一张表。实测同一输入：17 / 34 / 51 / 68 个描述符对应 level 1/2/3/4，四者全部 `VM-OK`。**关键踩坑**：提升器的最小载体门槛原按外层阶段标定（≥6 条指令），而 guest 块按构造就是短直线段，永远达不到该门槛 → 所有真实镜像都静默停在层 1，而单测因夹具程序很长仍然全绿；修法是按载体类型分开门槛（阶段 6 / guest 4）。退化现在会被报告：`PackResult::revirtualization_level` 记录实测深度，进度打印 `requested level N, engine established M`。回归新增 `x64_revirt_l1..l3` 三个用例，直接断言镜像内最深描述符层级 == 请求层级且镜像可运行。

27. `2.3.19` 修复「VM 扫描添加 2000+ 函数后卡在 59%、窗口无响应」。**根因不在引擎**：用 4832 个真实函数区间（`.pdata` 边界）压测，引擎 1.2 秒完成，问题在 UI 的日志渲染——
    - `ui/Pages/ProtectPage.xaml.cs` 的 `AppendLog()` 用 `LogBox.Text += line` 逐行追加。`LogBox` 是 `AcceptsReturn` + `TextWrapping="NoWrap"` 的只读 `TextBox`，每次赋值都要把整篇文本重新测量排版，于是 N 行日志的代价是 O(N²)。引擎对**每个被跳过的区域**打一行（`VM skip region: ...`），2000+ 函数就是 2000+ 行，UI 线程被彻底压死，而引擎早就跑完了 —— 现象就是进度停在最后一帧（59%）并显示"无响应"。
    - 修复：日志改为缓冲 + 定时刷写（120ms 的 `DispatcherQueueTimer`，构建期间启动、结束时停止并补一次 flush），并把文档上限设为 12 万字符只保留尾部；构建之外的日志仍即时显示。这样 2000 行只会触发约 8 次重排。
    - 引擎侧同时把逐条跳过日志改为**按原因计数**：`Packer::vmSkip()` 累加到 `vm_skip_counts_`，VM 阶段结束时打印一行汇总加每类原因一行。实测同一输入输出从 4832 行降到 29 行，并且比以前更有用（能直接看出为什么被拒：`uses RSP/RBP` / `no function body before RET` / `too small for trampoline` / `branch target outside translated range` / `unsupported instruction` …）。
    - **顺带暴露的既有行为**：VM 区域表上限是 64（`kMaxVmRegions`，运行时 `np_vm_install` 同样截断到 64）。选择 2000+ 函数时只有 RVA 最靠前的 64 个会真正被虚拟化，其余全部跳过——以前这条信息淹没在 2000 行里没人看见，现在会明确打印 `region table full - only the first 64 selected regions are virtualized`。**是否提高上限是独立决定**（要同时改打包器和运行时，并重新评估 trampoline 预算与镜像体积），本轮未改。
    - 回归：`tests/regress.ps1` → **59 OK / 0 FAIL**。
    - **未做**：guest 块不含内存操作（正确性优先的取舍）。
28. `2.3.20` 取消 VM 区域表 64 上限，改为「能虚拟化的全部虚拟化」。`kMaxVmRegions` 64 → 8192（打包器）与运行时 `np_vm_install` 的 `count > 64` 截断同步放开，8192 仅作损坏计数的防护上限（每个描述符仍按自身区域大小做边界检查，越界不会写出镜像）。**验证**：用汇编生成 200 个各 399 字节、只用 add/xor/shr/shl/sub/mov/ret 的叶子函数，按符号表区间打包 → **199/199 全部虚拟化，0 跳过**，受保护程序输出与原始完全一致（`ASMVF-OK 0000000012342D8B`）；改前同样输入最多 64 个。
    - **体积代价（实测，199×399 字节 = 78KB 原生代码）**：原文件 150KB → `-vm 5` 且开 revirtualization **2.93MB**；关掉 revirtualization 为 **683KB**。即 revirtualization 占了增量的约 80%（每区域约 11KB），基础 VM 约 2.7KB/区域。选择上千函数时建议降 `-revirt-level` 或 `-norevirtualization`，否则镜像会到几十 MB。
    - **仍未虚拟化的部分（技术原因，非人为上限）**：同一批测试里 `uses RSP/RBP` 是最大的一类——有栈帧的函数无法虚拟化，因为 trampoline 自己占用栈帧、VM 也没有栈指针语义；其次是 `unsupported instruction`（无基址 LEA、`movabs`、8/16 位寄存器形式等翻译器尚未覆盖的形式）与 `too small for trampoline`（区域小于 51+10×寄存器数+16 字节，放不下 trampoline）。这些会在日志里按原因计数打印，不再静默丢弃。
    - 顺带把 VM 阶段汇总行改为**始终打印**（以前只在有跳过时打印，全部成功时反而看不到虚拟化数量）。
    - 回归：`tests/regress.ps1` → **59 OK / 0 FAIL**。

29. `2.3.21` 提高 VM 覆盖率第一轮（针对「unsupported instruction / uses RSP-RBP / too small」三类拒绝原因）。**已完成**：无基址 LEA（`lea 0x0(,%rax,8),%rcx`，编译器数组下标的固定产物）与 `[disp32]` 绝对地址 LEA 现在可以翻译。关键坑：解码器把「无基址 SIB」的 base 记成 `Reg::RIP`（为了让寄存器掩码扫描不产生幽灵 RBP），必须用 `has_sib` 才能与真正的 RIP 相对寻址区分；真正的 RIP 相对仍然保持原生，因为它的地址依赖映像基址。验证：`manyfunc` 夹具的失败点从偏移 4（该 LEA）后移到偏移 0x34，`asmvf` 夹具仍 199/199 全部虚拟化且输出一致；回归 **59 OK / 0 FAIL**。在引擎自身 4832 个函数上实测：`unsupported instruction` 217 → 213，`8/16-bit` 8 → 6，**收益有限**——因为该二进制的第一大类是 `uses RSP/RBP`（1629）和 `no function body before RET`（2836）。
    - **未完成，但根因已定位**：
    - **IMUL**：`0F AF` 解码后 `dst`/`src`/`modrm`/`sib` **全部为空**（`parseModRM` 对该类别没有填充操作数），因此翻译器拿不到操作数、也无法从 ModRM 重建。这是"unsupported instruction"里最大的一项，修法在 `src/disasm.cpp` 的 `fixupOperands`/`parseModRM`，不在翻译器。注意 `imul` 还会写 CF/OF，而 wire ISA 的 `WIRE_MUL` 不设标志，所以修复时必须同时做标志活跃性检查，否则 `imul` 后的 `jo/jb` 会读到陈旧标志。
    - **uses RSP/RBP**：trampoline 的寄存器保存区就位于 guest RSP 之下（`sub rsp,144` 后 `[rsp+slot]`），region 内任何 push 或 `sub rsp,N` 都会写进保存区。**"多预留一些栈"解决不了**：函数只要分配一个大于预留量的局部帧，`[rsp+X]` 就会重新覆盖到保存区。真正的解法只有两条——把保存区搬到不占 guest 栈的地方（静态区需解决多线程重入，TEB/TLS 需先能分配内存），或先裁剪 prologue/epilogue、只虚拟化 body（body 内 RSP 稳定、`[rbp-X]` 落在 E 之上不冲突），后者可行但需要识别并验证栈平衡。属于 trampoline 栈模型改造，不是翻译器补漏。
    - **8/16 位寄存器形式**：wire 寄存器文件没有部分寄存器语义（写 AL 要保留 RAX 高 56 位），需要新增插入字节/字到寄存器的操作码，并处理 scratch 压力。
    - **too small for trampoline**：区域需容纳 `51+10×寄存器数+16` 字节。解法是把 trampoline 生成到独立可执行区、region 首部只留 5 字节 `jmp rel32`，最小区域从约 137 字节降到 5 字节；需要打包器预留 arena 并在头部记录偏移。


30. `2.3.22` VM 覆盖率第二轮：把上一轮定位的两个根因修掉。
    - **IMUL 现在可以翻译**。根因不在翻译器而在解码器：两字节操作码的 `needs_modrm` 判定只覆盖了 `0x00-0x3F / 0x40-0x4F / 0x90-0x9F / 0xB0-0xBF / 0x10-0x7F` 五段，而 `imul` 是 **`0xAF`**，恰好掉在 `0xB0` 下面一格——注释里还写着 "MOVZX/MOVSX/IMUL"，实际从来没生效。后果是 ModRM 从未被解析：`dst`/`src` 全空，**指令长度也少算 2 字节**。修法是给 `0xAF` 单独补一条 `needs_modrm`。翻译器侧同时补了标志位安全：`imul` 写 CF/OF，而 wire 的 `WIRE_MUL` 不设标志，所以用 `mulFlagsPending` 跟踪——若在下一个设置标志的指令之前遇到 JCC，直接结束该区域，避免分支读到陈旧标志。
    - **trampoline 搬到独立 arena**。原来 trampoline 直接生成在区域内，要求区域至少 `51+10×寄存器数+16` 字节；现在打包器在可执行的 `.np_prot` 里按每区域 `kTrampStride=384` 预留 arena（偏移记在头部 `+92`），`np_vm_install` 把 trampoline 生成到 arena、只在区域首部写 5 字节 `jmp rel32`。最小可虚拟化区域从约 137 字节降到 **5 字节**。**顺带修掉一个越界隐患**：原来的尺寸检查用 `51+10×regs`，但生成代码实际是 `51+20×regs`（寄存器文件既保存又恢复，各 10 字节），落在两者之间的区域会把 trampoline 写穿到后续代码里。arena 模式不再依赖区域大小，这个隐患自然消失；旧的原地模式也把系数改成 20 以防万一。
    - **实测**：`manyfunc` 夹具（158 个真实编译产物）**0 → 100 个区域虚拟化**；新增 `imul` 汇编夹具 119/119 全部虚拟化且输出与原程序逐字节一致；`asmvf` 仍 199/199；引擎自身 4832 个函数 **0 → 42**。回归 **59 OK / 0 FAIL**。
    - **剩余瓶颈（下一轮）**：`uses RSP/RBP` 1632、`no function body before RET` 2839。前者需要裁剪 prologue/epilogue、只虚拟化 body（body 内 RSP 稳定、`[rbp-X]` 落在入口 RSP 之上不与 trampoline 保存区冲突），并静态验证 body 不改写 RSP、不访问 `[rsp-k]`；后者需要先查清为什么 59% 的函数在 `.pdata` 区间内扫不到 RET。


## 生产验收

- [x] ZIP 中不包含 ASP.NET 项目、私有数据、密钥和旧 website service。
- [x] ZIP 安装脚本不创建新的 ASP.NET systemd 服务。
- [x] ZIP 根目录与 `deploy/` 安装入口均按包结构定位 `VERSION`，支持只读包校验。
- [x] Nginx 配置保留站点 listen/TLS/日志，并切换到 PHP-FPM。
- [x] 清理旧试验二进制、历史快照、调试文件和测试缓存；正式产物与签名材料保留。
- [ ] 上传 `artifacts/website-upgrade/2.2.14/` 下的升级 ZIP 后，在宝塔 Linux 实机执行 `bash upgrade.sh` 完成升级；新站点的 `/install` 应保持锁定。
- [ ] CDNfly 应用最高优先级动态规则并清理旧缓存后，运行 `bash deploy/cdnfly-check.sh https://nova.fbi.plus` 验收下载、`/api/*` 和 `Cache-Control: no-store`。

## 未决项

当前 Windows 工作区没有 Linux PHP-FPM 和 CDNfly 控制面，无法在本地替代宝塔实机验收；本轮已用本地 PHP CLI / 内置 HTTP 服务器完成客户端 EXE multipart 上传回归。上传 ZIP 后若失败，优先查看 `journalctl -u nginx`、宝塔 PHP-FPM 日志以及安装脚本生成的 `/www/server/novaprotect/backups/*`。

31. `2.3.33` 把延时复测抽查与沙箱检测做成默认成对启用：`-sandbox-guard` 未显式关闭时会自动带上 `0x2000` 位，`-no-audit-recheck` 保留单独开启的能力，安装包 PE 版本资源说明同步更新。
32. 官网与客户端版本线彻底解耦：网站版本只由 `website/VERSION` 决定，`release.json` 只保留客户端行；`package-website.ps1` 不再要求本地存在客户端安装包，`install.sh` 的 `downloads/` 改为可选，网站可以单独发版。
33. 客户端分发迁到 GitHub Releases：新增 `website/app/github.php`，`/download` 与 `/client-updates` 直接对接仓库，`/api/releases/current` 及其下载端点改为同源镜像（保留桌面更新器要求的同源路径、64 位十六进制 SHA-256 与字节数）。仓库地址写在 `github.json`，可用 `NOVAPROTECT_GITHUB_REPO` 覆盖。
34. 客户端更新检查改为直接读 GitHub Releases API：版本取自 tag，更新说明取自 release body，校验值取自资产 `sha256:` 摘要；下载按 GitHub 的 302 逐跳校验主机（仅 `github.com`、`objects.githubusercontent.com` 与 `*.githubusercontent.com`）。后台的客户端发布页签与上传通道已移除，分片上传只服务网站升级包。

35. `2.3.0` 官网改为纯静态站点，后台整体移除：删掉 PHP 应用（`app/*.php`、`public/index.php`、`public/.user.ini`）、管理员口令与一次性安装口令、分片上传传输（`upload.php`、`upload-progress.js`）、离线升级执行器（`upgrade-executor.*`）与安装向导；归档在 `artifacts/website-backend-legacy-2.2.31/`。站点现在是 6 个 HTML 页面 + `css/site.css` + `js/site.js` + `data/releases.json`：页面内容烘焙在 HTML 里，禁用 JS 也能读，`site.js` 只负责从 JSON 重绘更新日志与版本号，`fetch` 失败就保留烘焙内容。下载与更新日志指向 GitHub Releases，客户端本来就直连 GitHub，所以更新链路不受影响。`package-website.ps1` 改为只产出单包（`artifacts/website/<version>/NovaProtect-Website-<version>-Linux-x64-BaoTa.zip`），Full/Upgrade 双包区分取消——静态站重跑 `install.sh` 即升级。`install.sh` 不再装 PHP、不建服务、不生成口令，只放文件、从现有 vhost 继承 TLS、切槽位、重载 Nginx 并逐页验证；`rollback.sh`/`health-check.sh`/`cdnfly-check.sh` 一并改为静态断言（逐页 200、首页版本标记、未知路径必须 404）。`package-client-release.ps1` 的站点 E2E 换成不依赖站点的更新契约 smoke（`tests/update-client-smoke` 用 fixture transport 验 GitHub API 形状、摘要强制、重定向主机钉死）。验证：包校验 26 个文件、清单覆盖全量、`--check-package` 三种调用方式均通过、篡改/塞入未列文件/PHP 文件三个负例均正确失败、解包后静态服务器逐页 200 且 `/admin` `/index.php` `/api/*` 全部 404、`site.js` 14 项断言通过。
