CONTAINER_NAME = ghash

.PHONY: default
default: test_all

.PHONY: bench
bench:
	@rustup default nightly
	@echo -e "Rust Version:\n$$(rustc --version)\n" > Benchmark.txt
	@echo -e "Kernel Version:\n$$(uname -r)\n" >> Benchmark.txt
	@echo -e "CPU Information:\n$$(lscpu)\n" >> Benchmark.txt
	@cargo bench --bench lib >> Benchmark.txt
	@rustup default stable

test_all: test.x86_64-unknown-linux-gnu test.i686-unknown-linux-gnu test.wasm32-wasi

test.%:
	@$(MAKE) -C crate/hashes/blake test.$*
	@$(MAKE) -C crate/hashes/blake2 test.$*
	@$(MAKE) -C crate/hashes/edonr test.$*
	@$(MAKE) -C crate/hashes/keccak test.$*
	@$(MAKE) -C crate/hashes/md2 test.$*
	@$(MAKE) -C crate/hashes/md4 test.$*
	@$(MAKE) -C crate/hashes/md5 test.$*
	@$(MAKE) -C crate/hashes/ripemd test.$*
	@$(MAKE) -C crate/hashes/sha0 test.$*
	@$(MAKE) -C crate/hashes/sha1 test.$*
	@$(MAKE) -C crate/hashes/sha2 test.$*
	@$(MAKE) -C crate/hashes/sha3 test.$*
	@$(MAKE) -C crate/utils test.$*

test_build_std.%:
	@$(MAKE) -C crate/hashes/blake test_build_std.$*
	@$(MAKE) -C crate/hashes/blake2 test_build_std.$*
	@$(MAKE) -C crate/hashes/edonr test_build_std.$*
	@$(MAKE) -C crate/hashes/keccak test_build_std.$*
	@$(MAKE) -C crate/hashes/md2 test_build_std.$*
	@$(MAKE) -C crate/hashes/md4 test_build_std.$*
	@$(MAKE) -C crate/hashes/md5 test_build_std.$*
	@$(MAKE) -C crate/hashes/ripemd test_build_std.$*
	@$(MAKE) -C crate/hashes/sha0 test_build_std.$*
	@$(MAKE) -C crate/hashes/sha1 test_build_std.$*
	@$(MAKE) -C crate/hashes/sha2 test_build_std.$*
	@$(MAKE) -C crate/hashes/sha3 test_build_std.$*
	@$(MAKE) -C crate/utils test_build_std.$*

.PHONY: p.build
p.build:
	@podman build -t ${CONTAINER_NAME} .

.PHONY: run.bash
run.bash:
	-@podman run --name $@ -v .:/workdir -it ${CONTAINER_NAME} bash
	@podman rm $@
