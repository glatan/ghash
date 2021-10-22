test.armv7-unknown-linux-musleabihf:
ifeq ($(shell test $$(rustc --version | awk -F '.' '{print $$2}') -lt 56; echo $$?), 0)
	@cargo test -vv --target armv7-unknown-linux-musleabihf -- --skip tests
endif

test.%:
	@cargo test -vv --target $*

test_build_std.%:
	@cargo test -Z build-std -vv --target $*
