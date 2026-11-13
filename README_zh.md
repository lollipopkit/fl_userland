# iul — 通过原生 threaded-code 解释器在 iOS 上运行 Linux

一个 iOS 上的用户态 Linux 模拟器，可在 iPhone / iPad 上直接运行 **Python、Node.js、Go、Rust
和原生 CLI 工具**，在 Apple Silicon 上模拟 ARM64 Linux guest。

除 gadget 汇编外，引擎由 Rust 编写。

English: **[README.md](README.md)**

本仓库不含 app，交付的是嵌入方链接的引擎——一个静态库 `libiul.a`，每次推送到 `main`
都会以 `vX.Y.Z` release 发布。

## 构建

host 必须是 ARM64——gadget 只有 AArch64 一套。依赖：python3、clang + lld
（`brew install llvm lld`）、sqlite3、cargo。

```bash
tools/build-all.sh                                                # 全部产物，输出到 build/
tools/build-libs.sh build-ios --release --target aarch64-apple-ios  # 嵌入方链接的库
```

cross build 用 `build-libs.sh`（`fakefsify` 是 host 工具，不为手机构建）。
[ServerBox](https://github.com/lollipopkit/flutter_server_box) 以 submodule 方式引用本仓库，
直接下载发布产物而不自行构建。

构建期开关只有一个环境变量 `TMPFS_RS_CLANG_ARGS`，里面是 `-D` flag（如 `-DDEBUG_strace=1`
开启 syscall trace channel）；运行期诊断通过 `IUL_*` 环境变量控制（`IUL_EXEC_TRACE`、
`IUL_LOCK_TRACE` 等）。

## 运行

从 [Alpine 官网](https://alpinelinux.org/downloads/)下载 aarch64 的 minirootfs tarball，
转换成 fakefs 后启动 shell：

```bash
./build/tools/fakefsify alpine-minirootfs.tar.gz alpine
./build/iul -f alpine /bin/sh
```

## 测试

```bash
tools/checks.sh             # 源码分析
cargo test --workspace      # Rust 部分
tests/integration/smoke.sh  # 端到端
```

## 链接

- 使用方：[ServerBox](https://github.com/lollipopkit/flutter_server_box)

## 许可

GNU Affero General Public License 第 3 版，见 [LICENSE](LICENSE)。

少量代码衍生自 iSH 与 ish-arm64，这部分仍适用 GNU General Public License 第 3 版，文本见
[LICENSES](LICENSES)。
