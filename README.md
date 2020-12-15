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

1.43

## Tests

以下のターゲットでテストを通しています。(x86_64, wasm32以外はQEMUを使用)

### Stable

* aarch64-unknown-linux-gnu
* arm-unknown-linux-gnueabi
* arm-unknown-linux-gnueabihf
* armv5te-unknown-linux-gnueabi
* armv7-unknown-linux-gnueabi
* armv7-unknown-linux-gnueabihf
* i586-unknown-linux-gnu
* i686-pc-windows-msvc
* i686-unknown-linux-gnu
* mips-unknown-linux-gnu
* mips64-unknown-linux-gnuabi64
* mips64el-unknown-linux-gnuabi64
* mipsel-unknown-linux-gnu
* powerpc-unknown-linux-gnu
* powerpc64-unknown-linux-gnu
* powerpc64le-unknown-linux-gnu
* riscv64gc-unknown-linux-gnu
* s390x-unknown-linux-gnu
* sparc64-unknown-linux-gnu
* wasm32-wasi
* x86_64-pc-windows-msvc
* x86_64-unknown-linux-gnu

### MSRV

* aarch64-unknown-linux-gnu
* arm-unknown-linux-gnueabi
* arm-unknown-linux-gnueabihf
* armv5te-unknown-linux-gnueabi
* armv7-unknown-linux-gnueabi
* armv7-unknown-linux-gnueabihf
* i586-unknown-linux-gnu
* i686-unknown-linux-gnu
* mips-unknown-linux-gnu
* mips64-unknown-linux-gnuabi64
* mips64el-unknown-linux-gnuabi64
* mipsel-unknown-linux-gnu
* powerpc-unknown-linux-gnu
* powerpc64-unknown-linux-gnu
* powerpc64le-unknown-linux-gnu
* riscv64gc-unknown-linux-gnu
* s390x-unknown-linux-gnu
* sparc64-unknown-linux-gnu
* wasm32-wasi
* x86_64-unknown-linux-gnu

### Nightly

* aarch64-unknown-linux-gnu
* arm-unknown-linux-gnueabi
* arm-unknown-linux-gnueabihf
* armv5te-unknown-linux-gnueabi
* armv7-unknown-linux-gnueabi
* armv7-unknown-linux-gnueabihf
* i586-unknown-linux-gnu
* i686-unknown-linux-gnu
* mips-unknown-linux-gnu
* mips64-unknown-linux-gnuabi64
* mips64el-unknown-linux-gnuabi64
* mipsel-unknown-linux-gnu
* powerpc-unknown-linux-gnu
* powerpc64-unknown-linux-gnu
* powerpc64le-unknown-linux-gnu
* riscv64gc-unknown-linux-gnu
* s390x-unknown-linux-gnu
* sparc64-unknown-linux-gnu
* wasm32-wasi
* x86_64-unknown-linux-gnu

## Features

### default

デフォルトのターゲット

### minimal

defaultターゲットより出力バイナリのサイズが小さい。WebAssemblyを生成して、ブラウザで動作させるときはこっちの利用を推奨。それと多分こっちのほうが仕様書と比べながら読みやすい。

## License

This project is licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)
