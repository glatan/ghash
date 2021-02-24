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
	@$(MAKE) -C components/hashes/blake test.$*
	@$(MAKE) -C components/hashes/blake2 test.$*
	@$(MAKE) -C components/hashes/edonr test.$*
	@$(MAKE) -C components/hashes/keccak test.$*
	@$(MAKE) -C components/hashes/md2 test.$*
	@$(MAKE) -C components/hashes/md4 test.$*
	@$(MAKE) -C components/hashes/md5 test.$*
	@$(MAKE) -C components/hashes/ripemd test.$*
	@$(MAKE) -C components/hashes/sha0 test.$*
	@$(MAKE) -C components/hashes/sha1 test.$*
	@$(MAKE) -C components/hashes/sha2 test.$*
	@$(MAKE) -C components/hashes/sha3 test.$*
	@$(MAKE) -C components/utils test.$*

xargo_test.%:
	@$(MAKE) -C components/hashes/blake xargo_test.$*
	@$(MAKE) -C components/hashes/blake2 xargo_test.$*
	@$(MAKE) -C components/hashes/edonr xargo_test.$*
	@$(MAKE) -C components/hashes/keccak xargo_test.$*
	@$(MAKE) -C components/hashes/md2 xargo_test.$*
	@$(MAKE) -C components/hashes/md4 xargo_test.$*
	@$(MAKE) -C components/hashes/md5 xargo_test.$*
	@$(MAKE) -C components/hashes/ripemd xargo_test.$*
	@$(MAKE) -C components/hashes/sha0 xargo_test.$*
	@$(MAKE) -C components/hashes/sha1 xargo_test.$*
	@$(MAKE) -C components/hashes/sha2 xargo_test.$*
	@$(MAKE) -C components/hashes/sha3 xargo_test.$*
	@$(MAKE) -C components/utils xargo_test.$*

.PHONY: p.build
p.build:
	@podman build -t ${CONTAINER_NAME} .

.PHONY: run.bash
run.bash:
	-@podman run --name $@ -v .:/workdir -it ${CONTAINER_NAME} bash
	@podman rm $@
