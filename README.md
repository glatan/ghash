# Ghash

いろんなハッシュ関数を実装していくプロジェクト

## 実装しているハッシュ関数

* MD2
* MD4
* MD5
* SHA-0
* SHA-1
* SHA-2(224, 256, 384, 512, 512/224, 512/256)

## 入力サイズについて

入力バイト列の長さがusize(今のWebAssemblyなどの32bit環境では、32-bit unsigned integer。64bit環境では、64-bit unsigned integer)の最大値を超えるものには対応していません。

[MD4](https://tools.ietf.org/html/rfc1320)・[MD5](https://tools.ietf.org/html/rfc1321)のRFCには以下のような記載がありますが、これに対応するコードは実装されていません。

> In the unlikely event that b is greater than 2^64, then only
> the low-order 64 bits of b are used. (These bits are appended as two
> 32-bit words and appended low-order word first in accordance with the
> previous conventions.)

## License

This project is licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)
