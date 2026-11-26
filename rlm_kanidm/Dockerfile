ARG BASE_IMAGE=opensuse/tumbleweed:latest

FROM ${BASE_IMAGE} AS repos
ADD scripts/zypper_fixing.sh /zypper_fixing.sh
RUN --mount=type=cache,id=zypp,target=/var/cache/zypp,sharing=locked /zypper_fixing.sh

# ======================
FROM repos AS builder

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp,sharing=locked \
    zypper install -y \
    libopenssl-devel \
    clang \
    make \
    sccache \
    cargo \
    pkgconf-pkg-config \
    libtalloc-devel \
    freeradius-server-devel

RUN mkdir -p /src/kanidm
COPY . /src/kanidm/

WORKDIR /src/kanidm/

# FreeRADIUS does not correctly install it's own headers.
RUN cp rlm_kanidm/module/include/automask.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/connection.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/conffile.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/dlist.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/log.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/xlat.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/tmpl.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/token.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/clients.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/process.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/listen.h /usr/include/freeradius/

RUN ln -s /usr/include/freeradius /usr/include/freeradius-devel

RUN --mount=type=cache,id=cargo,target=/cargo \
    --mount=type=cache,id=sccache,target=/sccache \
    export CARGO_HOME=/cargo && \
    export SCCACHE_DIR=/sccache && \
    export RUSTC_WRAPPER=/usr/bin/sccache && \
    export CC="/usr/bin/clang" && \
    cargo build --locked -p rlm_kanidm --features extern-freeradius-module --lib --release && \
    cargo build --locked -p kanidm_radiusd --bin kanidm_radiusd --release && \
    sccache -s

# ======================
FROM repos AS final

ARG RADIUS_USER=radiusd
EXPOSE 1812 1813
ENV KANIDM_CONFIG_FILE="/data/radius.toml"

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp,sharing=locked \
    zypper install -y --no-recommends \
    freeradius-client \
    freeradius-server \
    freeradius-server-utils \
    openssl

ADD  rlm_kanidm/container/mods-available/ /etc/raddb/mods-available/
COPY rlm_kanidm/container/sites-available/ /etc/raddb/sites-available/

# Enable the native kanidm module and check-eap-tls virtual server.
RUN ln -s /etc/raddb/mods-available/kanidm_rust /etc/raddb/mods-enabled/kanidm && \
    ln -s /etc/raddb/sites-available/check-eap-tls /etc/raddb/sites-enabled/check-eap-tls

COPY --from=builder /src/kanidm/target/release/librlm_kanidm.so /usr/lib64/freeradius/rlm_kanidm.so
COPY --from=builder /src/kanidm/target/release/kanidm_radiusd /usr/local/bin/kanidm_radiusd

# # disable auth via methods we don't support!
RUN rm /etc/raddb/mods-available/sql && \
    rm /etc/raddb/mods-enabled/{passwd,totp}

# Allows the radiusd user to write to the directory
RUN chown -R $RADIUS_USER:$RADIUS_USER /etc/raddb/ && \
    mkdir -p /etc/raddb/certs && \
    chmod 775 /etc/raddb/certs && \
    chmod 640 /etc/raddb/clients.conf

RUN mkdir /data && chown radiusd /data && \
    mkdir -p /etc/raddb/certs/ && chmod a+r /etc/raddb/certs/ -R
USER $RADIUS_USER

CMD [ "/usr/local/bin/kanidm_radiusd" ]

