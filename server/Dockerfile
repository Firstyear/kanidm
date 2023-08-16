# Build the main Kanidmd server
ARG BASE_IMAGE=opensuse/tumbleweed:latest
FROM ${BASE_IMAGE} AS repos
RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper mr -k repo-oss; \
    zypper mr -k repo-non-oss; \
    zypper mr -k repo-update; \
    zypper ref --force ; \
    zypper -v dup -y

# ======================
FROM repos AS builder
ARG KANIDM_FEATURES
ARG KANIDM_BUILD_PROFILE="container_generic"
ARG KANIDM_BUILD_OPTIONS=""

# Set the build profile
ENV KANIDM_BUILD_PROFILE=${KANIDM_BUILD_PROFILE:-container_generic}
ENV RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=/usr/bin/ld.mold"

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y --no-recommends \
        sccache \
        cargo \
        clang \
        gawk \
        make automake autoconf \
        libopenssl-3-devel pam-devel \
        sqlite3-devel \
        rsync \
        findutils \
        which \
        mold

COPY . /usr/src/kanidm

# ======================

# WORKDIR /usr/src/kanidm/server/web_ui
# # This can't be used in the wasm build for now.
# # ENV RUSTFLAGS="-Clinker=clang"
# RUN ./build_wasm.sh

# ======================

WORKDIR /usr/src/kanidm/kanidmd/daemon

# Exports don't persist through RUN statements.
RUN \
--mount=type=cache,id=cargo,target=/cargo \
--mount=type=cache,id=sccache,target=/sccache \
export CARGO_HOME=/cargo; \
export SCCACHE_DIR=/sccache; \
export RUSTC_WRAPPER=/usr/bin/sccache; \
export CC="/usr/bin/clang"; \
    cargo build -p daemon ${KANIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/kanidm/target/" \
        --features="${KANIDM_FEATURES}" \
        --release; \
    sccache -s

# ======================

FROM repos

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y \
        timezone \
        openssl-3 \
        sqlite3 \
        pam

COPY --from=builder /usr/src/kanidm/target/release/kanidmd /sbin/
COPY --from=builder /usr/src/kanidm/server/web_ui/pkg /pkg
RUN chmod +x /sbin/kanidmd

EXPOSE 8443 3636
VOLUME /data

ENV RUST_BACKTRACE 1
CMD [ "/sbin/kanidmd", "server", "-c", "/data/server.toml"]
