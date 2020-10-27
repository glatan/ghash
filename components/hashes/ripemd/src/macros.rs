// minimal version
#[macro_export]
macro_rules! round_left_128_minimal {
    ($index_of_consts:expr, $t:expr, $a:expr, $b:expr, $c:expr, $d:expr, $f:ident, $x:expr, $range:expr) => {
        for j in $range {
            $t = $a
                .wrapping_add($f($b, $c, $d))
                .wrapping_add($x[R_LEFT[j]])
                .wrapping_add(K128_LEFT[$index_of_consts])
                .rotate_left(S_LEFT[j]);
            $a = $d;
            $d = $c;
            $c = $b;
            $b = $t;
        }
    };
}
#[macro_export]
macro_rules! round_right_128_minimal {
    ($index_of_consts:expr, $t:expr, $a:expr, $b:expr, $c:expr, $d:expr, $f:ident, $x:expr, $range:expr) => {
        for j in $range {
            $t = $a
                .wrapping_add($f($b, $c, $d))
                .wrapping_add($x[R_RIGHT[j]])
                .wrapping_add(K128_RIGHT[$index_of_consts])
                .rotate_left(S_RIGHT[j]);
            $a = $d;
            $d = $c;
            $c = $b;
            $b = $t;
        }
    };
}
#[macro_export]
macro_rules! round_left_160_minimal {
    ($index_of_consts:expr, $t:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:ident, $x:expr, $range:expr) => {
        for j in $range {
            $t = $a
                .wrapping_add($f($b, $c, $d))
                .wrapping_add($x[R_LEFT[j]])
                .wrapping_add(K160_LEFT[$index_of_consts])
                .rotate_left(S_LEFT[j])
                .wrapping_add($e);
            $a = $e;
            $e = $d;
            $d = $c.rotate_left(10);
            $c = $b;
            $b = $t;
        }
    };
}
#[macro_export]
macro_rules! round_right_160_minimal {
    ($index_of_consts:expr, $t:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:ident, $x:expr, $range:expr) => {
        for j in $range {
            $t = $a
                .wrapping_add($f($b, $c, $d))
                .wrapping_add($x[R_RIGHT[j]])
                .wrapping_add(K160_RIGHT[$index_of_consts])
                .rotate_left(S_RIGHT[j])
                .wrapping_add($e);
            $a = $e;
            $e = $d;
            $d = $c.rotate_left(10);
            $c = $b;
            $b = $t;
        }
    };
}
