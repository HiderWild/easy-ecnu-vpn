# EXV - 华东师范大学智能 VPN 客户端

EXV 是面向华东师范大学校园网的跨平台 VPN 客户端。它的核心目标很简单：连接校园 VPN 后，只让校内资源流量进入 VPN 隧道，其余互联网流量继续走本地网络，避免传统 VPN 默认路由接管全局流量。

当前项目已经完成从旧桌面壳和外部 OpenConnect 依赖到 native core + native WebView shell 的主路径迁移。生产桌面包不再捆绑 Electron/Chromium，也不把 OpenConnect 作为生产运行时依赖。

## 主要能力

- 分流路由：仅校园网段走 VPN，普通互联网访问保持本地出口。
- native WebView 桌面壳：`exv-ui` 使用系统 WebView 内核，Windows 为 WebView2，macOS 为 WKWebView，Linux 为 WebKitGTK。
- 原生 VPN 引擎：C++ core 负责认证、协议状态、重连策略和数据面协调。
- 特权 helper：以系统服务或一次性提权进程执行网卡、DNS、路由、清理等特权操作。
- 加密凭据存储：按平台使用系统加密能力或 OpenSSL 相关能力保存敏感配置。
- 稳定 RPC 契约：桌面 UI 通过 core RPC 和 helper contract 获取状态、触发连接、管理配置。
- 自动重连与状态事件：core 维护连接生命周期，UI 只负责交互和呈现。

## 快速开始

### 使用桌面应用

1. 构建或下载对应平台的 native WebView 桌面包。
2. 启动包内的 `exv-ui` 或 `exv-ui.exe`。
3. 首次使用时按提示安装或启动特权 helper。
4. 填写服务器、学号/账号、密码和路由设置。
5. 点击连接；断开时由 core 和 helper 清理路由、DNS 和隧道资源。

生产桌面包统一输出到：

```text
build/<platform>/webview/package/EXV
```

平台示例：

- Windows：`build\windows\webview\package\EXV`
- macOS：`build/macos/webview/package/EXV`
- Linux：`build/linux/webview/package/EXV`

包内关键文件：

- `exv-ui` / `exv-ui.exe`：native WebView 桌面壳。
- `exv-ui.args`：桌面壳启动参数清单。
- `bin/exv` / `bin/exv.exe`：core/CLI 进程。
- `bin/exv-helper` / `bin/exv-helper.exe`：特权 helper。
- `webui/index.html`：打包后的 Vue renderer。
- `WebView2Loader.dll`：Windows 包内 WebView2 loader。
- `EXV.app`：macOS 包内的标准 `.app` bundle，可直接拖入「应用程序」文件夹安装。

macOS 桌面包在 `build/macos/webview/package/EXV/` 下额外生成标准 `.app` bundle：

```text
EXV.app/
  Contents/
    Info.plist                 # CFBundleName、CFBundleIdentifier、版本号
    MacOS/EXV                  # exv-ui 桌面壳二进制
    Resources/
      exv-ui.args              # 相对路径，运行时由桌面壳解析
      bin/exv, bin/exv-helper  # core 与特权 helper
      webui/index.html         # Vue renderer
      icon.icns
```

`exv-ui.args` 内为相对路径（`bin/exv`、`webui/index.html`），`exv-ui` 在运行时依据自身 `Contents/Resources` 目录解析，因此 `EXV.app` 可整体拖动到任意路径（含「应用程序」文件夹）后直接启动。`Info.plist` 中的版本号取自 `CMakeLists.txt` 的 `project(exv VERSION ...)`。

Windows release packaging 输出到：

```text
build\windows\release\
```

发布产物：

- `EXV-<version>[-<build-label>]-windows-x64-portable.zip`: portable archive with a single top-level `EXV\` directory.
- `EXV-<version>[-<build-label>]-windows-x64-setup.exe`: per-user NSIS installer for `%LOCALAPPDATA%\Programs\EXV`.

`<version>` is the product version from `project(exv VERSION ...)` in `CMakeLists.txt`. Optional build labels such as `local-zh` only affect artifact names; Windows installed-app metadata and the in-app About version keep the product version.

setup 是面向 `%LOCALAPPDATA%\Programs\EXV` 的 per-user NSIS installer。它不捆绑 Microsoft Edge WebView2 Evergreen Runtime，也不在安装阶段安装 privileged helper；WebView2 Runtime 检测和 helper 安装仍由 app first-run flow 控制。

## 开发与构建

Windows 本地开发推荐入口：

```powershell
.\start.ps1
```

常用 Windows 参数：

```powershell
.\start.ps1 -Status          # 查看当前构建和 helper 状态
.\start.ps1 -Package         # 只生成 native WebView 包，不启动
.\start.ps1 -NoLaunch        # 构建并验证包，但不启动桌面壳
.\start.ps1 -NoFrontendBuild # 复用现有 renderer 产物
```

三平台桌面包构建：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1 desktop
```

```bash
./scripts/build-macos.sh desktop
./scripts/build-linux.sh desktop
```

只做 C++ core/helper 开发时，可使用 CMake preset：

```bash
cmake --preset <platform>-release
cmake --build --preset <platform>-release
ctest --preset <platform>-release --output-on-failure
```

Web renderer 单独编译：

```bash
pnpm --dir webui webview:compile
```

## 构建产物目录

- `build-windows/cpp`：Windows CMake 产物、测试和 `compile_commands.json`。
- `build/windows/webview/dist`：Windows renderer 产物。
- `build/windows/webview/package/EXV`：Windows native WebView 桌面包。
- `build/macos/cpp`：macOS CMake 产物和测试。
- `build/macos/webview/dist`：macOS renderer 产物。
- `build/macos/webview/package/EXV`：macOS native WebView 桌面包。
- `build/linux/cpp`：Linux CMake 产物和测试。
- `build/linux/webview/dist`：Linux renderer 产物。
- `build/linux/webview/package/EXV`：Linux native WebView 桌面包。

## 运行时依赖

- Windows：Microsoft Edge WebView2 Evergreen Runtime。缺失时 `exv-ui` 会按受控流程提示安装。
- macOS：系统 WKWebView。
- Linux：WebKitGTK 运行时和开发包；加密相关能力依赖 OpenSSL。
- Windows 原生隧道资产：`wintun.dll`。

OpenConnect 只保留为历史兼容或诊断对照语境，不是生产桌面包的必需运行时。

## 配置

默认配置文件位置：

- Windows：`%LOCALAPPDATA%\EXV\profile\default\config.json`
- macOS：`~/Library/Application Support/EXV/profile/default/config.json`
- Linux：`~/.exv/config.json`

示例配置：

```json
{
  "server": "https://vpn-ct.ecnu.edu.cn",
  "username": "20XXXXXXXXX",
  "password": "<encrypted>",
  "mtu": 1290,
  "routes": ["49.52.4.0/25"],
  "webui_enabled": false
}
```

配置文件保存用户意图和偏好。活动网卡、DNS 快照、清理计划、helper lease 等运行时事实由 core/helper 运行时状态管理，不写入用户配置。

## 技术栈

- C++20 + CMake 3.28+
- Vue 3 + TypeScript + Vite
- native WebView shell：WebView2 / WKWebView / WebKitGTK
- nlohmann/json
- cpp-httplib
- Wintun / utun / Linux network stack

## 文档入口

- 日常使用：[docs/user_guide.md](docs/user_guide.md)
- 构建矩阵：[docs/build_guide.md](docs/build_guide.md)
- 当前架构：[docs/PROJECT_CURRENT_ARCHITECTURE.md](docs/PROJECT_CURRENT_ARCHITECTURE.md)
- 运行时资产：[docs/runtime-assets.md](docs/runtime-assets.md)
- Windows WebView2 失焦输入问题归档：[docs/archive/2026-06/reports/2026-06-21-win32-webview2-focus-input-resolution.md](docs/archive/2026-06/reports/2026-06-21-win32-webview2-focus-input-resolution.md)

## License

[MIT](LICENSE)
