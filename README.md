# Ghash

いろんなハッシュ関数を実装していくプロジェクト

## About

基本的に仕様書に準じた素朴な実装になっているため、各ハッシュ関数の仕様を学ぶ用途には多分適しています。

自分のプロジェクトでハッシュ関数を使いたい場合は、より高速な他の実装を利用することをおすすめします。

## 実装しているハッシュ関数

* BLAKE-{28, 32, 48, 64, 224, 256, 384, 512}
* BLAKE2s
* BLAKE2b
* Keccak-{224, 256, 384, 512}
* MD2
* MD4
* MD5
* RIPEMD-{128, 160, 256, 320}
* SHA-0
* SHA-1
* SHA-{224, 256, 384, 512, 512/224, 512/256}
* SHA3-{224, 256, 384, 512}

### Demo

WebAssemblyターゲットでビルドしたデモが[ここ](https://ghash.glatan.vercel.app/)にあります。

### Targets

以下のターゲットでテストを通しています。(x86_64, wasm32以外はQEMUを使用)

* aarch64-unknown-linux-gnu
* arm-unknown-linux-gnueabi
* arm-unknown-linux-gnueabihf
* armv5te-unknown-linux-gnueabi
* armv7-unknown-linux-gnueabihf
* armv7-unknown-linux-gnueabi
* i586-unknown-linux-gnu
* i686-unknown-linux-gnu
* mips-unknown-linux-gnu
* mipsel-unknown-linux-gnu
* mips64-unknown-linux-gnuabi64
* mips64el-unknown-linux-gnuabi64
* powerpc-unknown-linux-gnu
* powerpc64-unknown-linux-gnu
* powerpc64le-unknown-linux-gnu
* riscv64gc-unknown-linux-gnu
* s390x-unknown-linux-gnu
* sparc64-unknown-linux-gnu
* wasm32-wasi

## License

This project is licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)
