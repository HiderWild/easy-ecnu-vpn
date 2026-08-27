// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// C02-E：descriptor set 字节（exv.vpn.v1.descriptor.bin）由 build.rs 生成并编入本
// crate，用于 gRPC reflection / 服务描述。生成文件位于 target/OUT_DIR 下，不提交。

/// 序列化后的 `exv.vpn.v1` FileDescriptorSet 字节。
pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("exv.vpn.v1.descriptor");
