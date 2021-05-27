# Ghash

いろんなハッシュ関数を実装していくプロジェクト(基本的に`#![no_std]`)

## About

基本的に仕様書に準じた素朴な実装になっているため、各ハッシュ関数の仕様を学ぶ用途には多分適しています。

自分のプロジェクトでハッシュ関数を使いたい場合は、より高速な他の実装を利用することをおすすめします。

## 実装しているハッシュ関数

* BLAKE-{28, 32, 48, 64, 224, 256, 384, 512}
* BLAKE2s
* BLAKE2b
* EDON-R{224, 256, 384, 512}
* Keccak-f{200, 400, 800, 1600}
* Keccak-{224, 256, 384, 512}
* MD2
* MD4
* MD5
* RIPEMD-{128, 160, 256, 320}
* SHA-0
* SHA-1
* SHA-{224, 256, 384, 512, 512/224, 512/256}
* SHA3-{224, 256, 384, 512}
* SHAKE128, SHAKE256

## Example

* WebAssemblyターゲットでビルドしたデモが[ここ](https://ghash.glatan.vercel.app/)にあります。
* PSP(PlayStation Portable)ターゲットのデモは[ここ](https://gitlab.com/glatan/ghash-psp)。

## MSRV(Minimum Supported Rust Version)

1.50

## Tests

以下のターゲットでテストを通しています。

* OS: ubuntu:hirsute

### Stable, MSRV, Nightly

|Target|Linker|Runner + Option|Note|
|-|-|-|-|
|aarch64-unknown-linux-gnu|aarch64-linux-gnu-gcc|qemu-aarch64 -L /usr/aarch64-linux-gnu/||
|aarch64-unknown-linux-musl|aarch64-linux-gnu-gcc|qemu-aarch64 -L /usr/aarch64-linux-gnu/||
|arm-unknown-linux-gnueabi|arm-linux-gnueabi-gcc|qemu-arm -L /usr/arm-linux-gnueabi/||
|arm-unknown-linux-gnueabihf|arm-linux-gnueabihf-gcc|qemu-arm -L /usr/arm-linux-gnueabihf/||
|arm-unknown-linux-musleabi|arm-linux-gnueabi-gcc|qemu-arm -L /usr/arm-linux-gnueabi/||
|arm-unknown-linux-musleabihf|arm-linux-gnueabihf-gcc|qemu-arm -L /usr/arm-linux-gnueabihf/||
|armv5te-unknown-linux-gnueabi|arm-linux-gnueabi-gcc|qemu-arm -L /usr/arm-linux-gnueabi/||
|armv5te-unknown-linux-musleabi|arm-linux-gnueabi-gcc|qemu-arm -L /usr/arm-linux-gnueabi/||
|armv7-unknown-linux-gnueabi|arm-linux-gnueabi-gcc|qemu-arm -L /usr/arm-linux-gnueabi/||
|armv7-unknown-linux-gnueabihf|arm-linux-gnueabihf-gcc|qemu-arm -L /usr/arm-linux-gnueabihf/||
|armv7-unknown-linux-musleabi|arm-linux-gnueabi-gcc|qemu-arm -L /usr/arm-linux-gnueabi/||
|armv7-unknown-linux-musleabihf|arm-linux-gnueabihf-gcc|qemu-arm -L /usr/arm-linux-gnueabihf/||
|i586-unknown-linux-gnu|i686-linux-gnu-gcc|qemu-i386 -L /usr/i686-linux-gnu/||
|i586-unknown-linux-musl|i686-linux-gnu-gcc|qemu-i386 -L /usr/i686-linux-gnu/||
|i686-pc-windows-msvc||||
|i686-unknown-linux-gnu|i686-linux-gnu-gcc|qemu-i386 -L /usr/i686-linux-gnu/||
|i686-unknown-linux-musl|i686-linux-gnu-gcc|qemu-i386 -L /usr/i686-linux-gnu/||
|mips-unknown-linux-gnu|mips-linux-gnu-gcc|qemu-mips -L /usr/mips-linux-gnu/||
|mips-unknown-linux-musl|mips-linux-gnu-gcc|qemu-mips -L /usr/mips-linux-gnu/|RUSTFLAGS="-C target-feature=+crt-static"|
|mips64-unknown-linux-gnuabi64|mips64-linux-gnuabi64-gcc|qemu-mips64 -L /usr/mips64-linux-gnuabi64/||
|mips64-unknown-linux-muslabi64|mips64-linux-gnuabi64-gcc|qemu-mips64 -L /usr/mips64-linux-gnuabi64/||
|mips64el-unknown-linux-gnuabi64|mips64el-linux-gnuabi64-gcc|qemu-mips64el -L /usr/mips64el-linux-gnuabi64/||
|mips64el-unknown-linux-muslabi64|mips64el-linux-gnuabi64-gcc|qemu-mips64el -L /usr/mips64el-linux-gnuabi64/||
|mipsel-unknown-linux-gnu|mipsel-linux-gnu-gcc|qemu-mipsel -L /usr/mipsel-linux-gnu/||
|mipsel-unknown-linux-musl|mipsel-linux-gnu-gcc|qemu-mipsel -L /usr/mipsel-linux-gnu/|RUSTFLAGS="-C target-feature=+crt-static"|
|powerpc-unknown-linux-gnu|powerpc-linux-gnu-gcc|qemu-ppc -L /usr/powerpc-linux-gnu/||
|powerpc64-unknown-linux-gnu|powerpc64-linux-gnu-gcc|qemu-ppc64 -L /usr/powerpc64-linux-gnu/||
|powerpc64le-unknown-linux-gnu|powerpc64le-linux-gnu-gcc|qemu-ppc64le -L /usr/powerpc64le-linux-gnu/||
|riscv64gc-unknown-linux-gnu|riscv64-linux-gnu-gcc|qemu-riscv64 -L /usr/riscv64-linux-gnu/||
|s390x-unknown-linux-gnu|s390x-linux-gnu-gcc|qemu-s390x -L /usr/s390x-linux-gnu/||
|sparc64-unknown-linux-gnu|sparc64-linux-gnu-gcc|qemu-sparc64 -L /usr/sparc64-linux-gnu/||
|thumbv7neon-unknown-linux-gnueabihf|arm-linux-gnueabihf-gcc|qemu-arm -L /usr/arm-linux-gnueabihf/||
|wasm32-wasi||wasmtime||
|x86_64-pc-windows-msvc||||
|x86_64-unknown-linux-gnu||||
|x86_64-unknown-linux-musl||||

### Tier 3(Nightly Only)

|Target|Linker|Runner + Option|Note|
|-|-|-|-|
|mipsisa32r6-unknown-linux-gnu|mipsisa32r6-linux-gnu-gcc|qemu-mips -L /usr/mipsisa32r6-linux-gnu/||
|mipsisa32r6el-unknown-linux-gnu|mipsisa32r6el-linux-gnu-gcc|qemu-mipsel -L /usr/mipsisa32r6el-linux-gnu/||
|mipsisa64r6-unknown-linux-gnuabi64|mipsisa64r6-linux-gnuabi64-gcc|qemu-mips64 -L /usr/mipsisa64r6-linux-gnuabi64/||
|mipsisa64r6el-unknown-linux-gnuabi64|mipsisa64r6el-linux-gnuabi64-gcc|qemu-mips64el -L /usr/mipsisa64r6el-linux-gnuabi64/||

## Features

### default

デフォルトのターゲット

### minimal

defaultターゲットより出力バイナリのサイズが小さい。WebAssemblyを生成して、ブラウザで動作させるときはこっちの利用を推奨。それと多分こっちのほうが仕様書と比べながら読みやすい。

## License

This project is licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)
