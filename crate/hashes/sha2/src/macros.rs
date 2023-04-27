#[macro_export]
macro_rules! init_w32 {
    ($w:expr, $( $t:expr ),* ) => {
        $(
            $w[$t] = small_sigma32_1($w[$t - 2])
                .wrapping_add($w[$t - 7])
                .wrapping_add(small_sigma32_0($w[$t - 15]))
                .wrapping_add($w[$t - 16]);
        )*
    };
}
#[macro_export]
macro_rules! init_w64 {
    ($w:expr, $( $t:expr ),*) => {
        $(
            $w[$t] = small_sigma64_1($w[$t - 2])
                .wrapping_add($w[$t - 7])
                .wrapping_add(small_sigma64_0($w[$t - 15]))
                .wrapping_add($w[$t - 16]);
        )*
    };
}

#[macro_export]
macro_rules! round_32 {
    ($temp_1:expr, $temp_2:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $w:expr, $( $t:expr ),+) => {
        $(
            $temp_1 = $h
                .wrapping_add(big_sigma32_1($e))
                .wrapping_add(ch32($e, $f, $g))
                .wrapping_add(K32[$t])
                .wrapping_add($w[$t]);
            $temp_2 = big_sigma32_0($a).wrapping_add(maj32($a, $b, $c));
            $h = $g;
            $g = $f;
            $f = $e;
            $e = $d.wrapping_add($temp_1);
            $d = $c;
            $c = $b;
            $b = $a;
            $a = $temp_1.wrapping_add($temp_2);
        )*
    };
}
#[macro_export]
macro_rules! round_64 {
    ($temp_1:expr, $temp_2:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $w:expr, $( $t:expr ),+) => {
        $(
            $temp_1 = $h
                .wrapping_add(big_sigma64_1($e))
                .wrapping_add(ch64($e, $f, $g))
                .wrapping_add(K64[$t])
                .wrapping_add($w[$t]);
            $temp_2 = big_sigma64_0($a).wrapping_add(maj64($a, $b, $c));
            $h = $g;
            $g = $f;
            $f = $e;
            $e = $d.wrapping_add($temp_1);
            $d = $c;
            $c = $b;
            $b = $a;
            $a = $temp_1.wrapping_add($temp_2);
        )*
    };
}
