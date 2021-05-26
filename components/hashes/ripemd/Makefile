test.%:
	@cargo test -vv --target $*
	@cargo test -vv --target $* --features minimal

test_build_std.%:
	@cargo test -Z build-std -vv --target $*
	@cargo test -Z build-std -vv --target $* --features minimal
