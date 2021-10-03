FROM docker.io/ubuntu:hirsute

WORKDIR /workdir

ENV CARGO_HOME='/cargo' \
    PATH="${PATH}:/cargo/bin" \
    MSRV='1.50' \
    WASMTIME_VERSION='0.25.0' \
    XARGO_VERSION='0.3.20' \
    TARGETS='\
        aarch64-unknown-linux-gnu \
        aarch64-unknown-linux-musl \
        arm-unknown-linux-gnueabi \
        arm-unknown-linux-gnueabihf \
        arm-unknown-linux-musleabi \
        arm-unknown-linux-musleabihf \
        armv5te-unknown-linux-gnueabi \
        armv5te-unknown-linux-musleabi \
        armv7-unknown-linux-gnueabi \
        armv7-unknown-linux-gnueabihf \
        armv7-unknown-linux-musleabi \
        armv7-unknown-linux-musleabihf \
        i586-unknown-linux-gnu \
        i586-unknown-linux-musl \
        i686-unknown-linux-gnu \
        i686-unknown-linux-musl \
        mips-unknown-linux-gnu \
        mips-unknown-linux-musl \
        mips64-unknown-linux-gnuabi64 \
        mips64-unknown-linux-muslabi64 \
        mips64el-unknown-linux-gnuabi64 \
        mips64el-unknown-linux-muslabi64 \
        mipsel-unknown-linux-gnu \
        mipsel-unknown-linux-musl \
        powerpc-unknown-linux-gnu \
        powerpc64-unknown-linux-gnu \
        powerpc64le-unknown-linux-gnu \
        riscv64gc-unknown-linux-gnu \
        s390x-unknown-linux-gnu \
        sparc64-unknown-linux-gnu \
        thumbv7neon-unknown-linux-gnueabihf \
        x86_64-unknown-linux-gnu \
        x86_64-unknown-linux-musl \
        wasm32-wasi'

RUN \
    apt update -y && \
    apt install -y \
        curl \
        make \
        qemu-user \
        xz-utils \
        gcc-aarch64-linux-gnu \
        gcc-arm-linux-gnueabi \
        gcc-arm-linux-gnueabihf \
        gcc-arm-linux-gnueabi \
        gcc-arm-linux-gnueabi \
        gcc-arm-linux-gnueabihf \
        gcc-i686-linux-gnu \
        gcc-i686-linux-gnu \
        gcc-mips-linux-gnu \
        gcc-mipsel-linux-gnu \
        gcc-mips64-linux-gnuabi64 \
        gcc-mips64el-linux-gnuabi64 \
        gcc-powerpc-linux-gnu \
        gcc-powerpc64-linux-gnu \
        gcc-powerpc64le-linux-gnu \
        gcc-riscv64-linux-gnu \
        gcc-s390x-linux-gnu \
        gcc-sparc64-linux-gnu \
        gcc

RUN \
    curl -L "https://github.com/bytecodealliance/wasmtime/releases/download/v${WASMTIME_VERSION}/wasmtime-v${WASMTIME_VERSION}-x86_64-linux.tar.xz" > wasmtime-v${WASMTIME_VERSION}-x86_64-linux.tar.xz && \
    tar -xvf wasmtime-v${WASMTIME_VERSION}-x86_64-linux.tar.xz && \
    mv wasmtime-v${WASMTIME_VERSION}-x86_64-linux/wasmtime /usr/bin/

RUN \
    curl https://sh.rustup.rs -sSf > install.sh && \
    sh install.sh -y --default-toolchain stable --profile minimal && \
    rustup target add ${TARGETS} && \
    rustup default "${MSRV}" && \
    rustup target add ${TARGETS} && \
    rustup default nightly && \
    rustup target add ${TARGETS}

RUN \
    rustup component add rust-src
