# Ghash

いろんなハッシュ関数を実装していくプロジェクト

## About

基本的に仕様書に準じた素朴な実装になっているため、各ハッシュ関数の仕様を学ぶ用途には多分適しています。

自分のプロジェクトでハッシュ関数を使いたい場合は、より高速な他の実装を利用することをおすすめします。

## 実装しているハッシュ関数

* BLAKE-{224, 256, 384, 512}
* MD2
* MD4
* MD5
* RIPEMD-{128, 160, 256, 320}
* SHA-0
* SHA-1
* SHA-{224, 256, 384, 512, 512/224, 512/256}

## 入力サイズについて

入力ビット列の長さがusize(今のWebAssemblyなどの32bit環境では、32-bit unsigned integer・64bit環境では、64-bit unsigned integerなど)の最大値を超えるものには現在対応していません。そのため、下記の例のようなことが起こります。(1バイトは8ビットであるものとしています)

例: usize = u32、入力バイト列の長さをlengthとし、`u32::MAX < (length * 8) < u64::MAX`となるとき、利用するハッシュ関数が`u64::MAX`ビット未満の入力をサポートしていても、この入力のハッシュ値は計算されません。

また、[MD4](https://tools.ietf.org/html/rfc1320)・[MD5](https://tools.ietf.org/html/rfc1321)のRFCには以下のような記載がありますが、これに対応するコードは実装されていません。これはMD4と同様のパディングを行うRIPEMD-{128, 160, 256, 320}・SHA-0・SHA-1・SHA-{224, 256}でも同じです。

> In the unlikely event that b is greater than 2^64, then only
> the low-order 64 bits of b are used. (These bits are appended as two
> 32-bit words and appended low-order word first in accordance with the
> previous conventions.)

## License

This project is licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)
