// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// C02-E：可复现 generation 与 descriptor baseline。
//   * 使用 vendored protoc（protoc_bin_vendored::protoc_bin_path()），通过
//     tonic_prost_build::Config::protoc_executable 显式传给 prost-build/tonic，
//     因此无需系统 protoc 在 PATH 上。
//   * 生成 server + client 以及 exv.vpn.v1 descriptor set。
//   * 不修改 PATH、不调用 CMake、不提交生成 .rs（生成发生在 target/OUT_DIR 构建期）。

use std::env;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // vendored protoc 二进制路径；独立于系统 PATH，保证可复现。
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // build.rs 的 CWD 是包根目录（src/common/rust/crates/exv-vpn-wire）。
    // proto 根位于仓库根目录的 proto/ 下，相对本 crate 向上 5 级。
    // protoc 以 CWD 相对路径解析输入文件，故用相对路径而非绝对路径。
    let proto_include = Path::new("../../../../../proto");
    assert!(
        proto_include.is_dir(),
        "proto include root not found relative to crate root: {} (CWD={})",
        proto_include.display(),
        env::current_dir()?.display()
    );

    let protos = [
        proto_include.join("exv/v1/common.proto"),
        proto_include.join("exv/v1/kernel_control.proto"),
        proto_include.join("exv/v1/helper_control.proto"),
        proto_include.join("exv/v1/packet_relay.proto"),
    ];
    for p in &protos {
        assert!(p.is_file(), "proto file not found: {}", p.display());
    }
    // C02-E: proto files are the build input — any edit must regenerate the bindings.
    // Without this, cargo treats the build script as unchanged and silently reuses the
    // stale generated code (P3-b1 hit exactly this: a proto edit did not rebuild).
    for p in &protos {
        println!("cargo:rerun-if-changed={}", p.display());
    }

    // 将 vendored protoc 显式配置到 prost-build config。
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc);

    tonic_prost_build::configure()
        // KernelControl 服务含 `rpc Connect`，生成的 client 方法 `connect` 会与 tonic
        // client 内建 transport `connect` 构造器重名。关闭 transport helper 以消解该
        // 冲突（client 仍生成全部 RPC 方法；server 不受影响）。
        .build_transport(false)
        // descriptor set 编入 wire crate（descriptor.rs 用 include_file_descriptor_set! 引用）。
        .file_descriptor_set_path(out_dir.join("exv.vpn.v1.descriptor.bin"))
        .compile_with_config(
            config,
            &protos,
            // include root：proto/ 目录；proto 内部 import 形如 "exv/v1/common.proto"。
            &[proto_include.to_path_buf()],
        )?;

    Ok(())
}
