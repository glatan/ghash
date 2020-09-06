.PHONY: bench
bench:
	@rustup default nightly
	@echo -e "Rust Version:\n$$(rustc --version)\n" > Benchmark.txt
	@echo -e "Kernel Version:\n$$(uname -r)\n" >> Benchmark.txt
	@echo -e "CPU Information:\n$$(lscpu)\n" >> Benchmark.txt
	@cargo bench --bench lib >> Benchmark.txt
	@rustup default stable
