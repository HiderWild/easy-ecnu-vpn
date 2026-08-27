// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// C02-E：include 构建期由 build.rs 生成的 prost/tonic 代码（exv.vpn.v1 包的
// message + service server/client）。生成文件位于 target/OUT_DIR 下，不提交。

tonic::include_proto!("exv.vpn.v1");
