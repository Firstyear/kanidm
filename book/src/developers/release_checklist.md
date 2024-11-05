# Release Checklist

## Pre-Reqs

```bash
cargo install cargo-audit
cargo install cargo-outdated
cargo install cargo-udeps
cargo install cargo-machete
```

## Pre Release Check List

### Start a release

- [ ] git checkout -b YYYYMMDD-pre-release

### Cargo Tasks

- [ ] Update MSRV if applicable
- [ ] cargo update
- [ ] `RUSTC_BOOTSTRAP=1 cargo udeps`
- [ ] `cargo machete`
- [ ] cargo outdated -R
- [ ] cargo audit
- [ ] cargo test

- [ ] setup a local instance and run orca (TBD)
- [ ] store a copy an an example db (TBD)

### Code Changes

- [ ] upgrade crypto policy values if required
- [ ] check for breaking db entry changes.

### Administration

- [ ] Update `RELEASE_NOTES.md`
- [ ] Update `README.md`
- [ ] cargo test
- [ ] git commit -a -m "Release Notes"
- [ ] git push origin YYYYMMDD-pre-release
- [ ] Merge PR

### Git Management

- [ ] git checkout master
- [ ] git pull
- [ ] git checkout -b 1.x.0 (Note no v to prevent ref conflict)
- [ ] update version to set pre tag in ./Cargo.toml
- [ ] git commit -m "Release 1.x.0-pre"
- [ ] git tag v1.x.0-pre

- [ ] Final inspect of the branch

- [ ] git push origin 1.x.0 --tags

- [ ] github -> Ensure release branch is protected

### Follow up

- [ ] git checkout master
- [ ] git pull
- [ ] git checkout -b YYYYMMDD-dev-version
- [ ] update version to +1 and add dev tag in ./Cargo.toml
- [ ] update `DOMAIN_*_LEVEL` in server/lib/src/constants/mod.rs
- [ ] update and add new migrations

## Final Release Check List

### Git Management Part Deux

- [ ] git checkout 1.x.0
- [ ] git pull origin 1.x.0

- [ ] update version to remove pre tag in ./Cargo.toml
- [ ] update Makefile to set docker image to latest
- [ ] git commit -a -m 'Release 1.x.0'
- [ ] git tag v1.x.0
- [ ] git push origin 1.x.0 --tags

- [ ] github -> create new release based on tag (not branch) - use tag because then tools will get
      the tag + patches we apply.

### Community

- [ ] Publish release announcement

### Cargo publish

- [ ] publish `scim_proto`
- [ ] publish `kanidm_proto`
- [ ] publish `sketching`
- [ ] publish `kanidm_utils_users`
- [ ] publish `kanidm_lib_file_permissions`
- [ ] publish `kanidm_lib_crypto`
- [ ] publish `kanidm_build_profiles`
- [ ] publish `kanidm_client`
- [ ] publish `kanidm_tools`

### Docker

- [ ] docker buildx use cluster
- [ ] `make buildx`
- [ ] Update the readme on docker <https://hub.docker.com/repository/docker/kanidm/server>

### Distro

- [ ] vendor and release to build.opensuse.org

