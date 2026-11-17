# Makefile for Kanidm


CONTAINER_TOOL ?= docker
CONTAINER_TOOL_ARGS ?=
CONTAINER_BUILD_ARGS ?=
CONTAINER_IMAGE_BASE ?= kanidm
CONTAINER_IMAGE_VERSION ?= devel
CONTAINER_IMAGE_EXT_VERSION ?= $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "daemon")  | .version')
# CONTAINER_BUILDX_ACTION is used to specify the action for buildx, e.g., --push or --load
CONTAINER_BUILDX_ACTION ?= --push
# CONTAINER_IMAGE_ARCH is used to specify the architectures for multi-arch docker builds
CONTAINER_IMAGE_ARCH ?= "linux/amd64,linux/arm64"
BUILDKIT_PROGRESS ?= plain
COSIGN_CMD = cosign sign --recursive=true

KANIDM_FEATURES ?= ""

# MARKDOWN_FORMAT_ARGS is used to specify additional arguments for markdown formatting
MARKDOWN_FORMAT_ARGS ?=
BOOK_VERSION ?= master

GIT_COMMIT := $(shell git rev-parse HEAD)

.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'


.PHONY: config
config: ## Show makefile config things
config:
	@echo "CONTAINER_IMAGE_BASE: $(CONTAINER_IMAGE_BASE)"
	@echo "CONTAINER_IMAGE_VERSION: $(CONTAINER_IMAGE_VERSION)"
	@echo "CONTAINER_IMAGE_EXT_VERSION: $(CONTAINER_IMAGE_EXT_VERSION)"
	@echo "CONTAINER_TOOL: $(CONTAINER_TOOL)"
	@echo "CONTAINER_TOOL_ARGS: $(CONTAINER_TOOL_ARGS)"
	@echo "CONTAINER_BUILDX_ACTION: $(CONTAINER_BUILDX_ACTION)"
	@echo "CONTAINER_IMAGE_ARCH: $(CONTAINER_IMAGE_ARCH)"
	@echo "CONTAINER_BUILD_ARGS: $(CONTAINER_BUILD_ARGS)"
	@echo "MARKDOWN_FORMAT_ARGS: $(MARKDOWN_FORMAT_ARGS)"
	@echo "BUILDKIT_PROGRESS: $(BUILDKIT_PROGRESS)"
	@echo "BOOK_VERSION: $(BOOK_VERSION)"
	@echo "GIT_COMMIT: $(GIT_COMMIT)"

.PHONY: run
run: ## Run the test/dev server
run:
	scripts/run_insecure_dev_server.sh

.PHONY: run_htmx
run_htmx: ## Run in HTMX mode
run_htmx:
	KANI_CARGO_OPTS="--features kanidmd_core/ui_htmx" scripts/run_insecure_dev_server.sh

.PHONY: buildx/kanidmd
buildx/kanidmd: ## Build multiarch kanidm server images and push to docker hub
buildx/kanidmd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull $(CONTAINER_BUILDX_ACTION) --platform $(CONTAINER_IMAGE_ARCH) \
		-f server/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION) \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_EXT_VERSION) \
		--progress $(BUILDKIT_PROGRESS) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=$(KANIDM_FEATURES)" \
		--compress \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: buildx/kanidm_tools
buildx/kanidm_tools: ## Build multiarch kanidm tool images and push to docker hub
buildx/kanidm_tools:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull $(CONTAINER_BUILDX_ACTION) --platform $(CONTAINER_IMAGE_ARCH) \
		-f tools/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/tools:$(CONTAINER_IMAGE_VERSION) \
		-t $(CONTAINER_IMAGE_BASE)/tools:$(CONTAINER_IMAGE_EXT_VERSION) \
		--progress $(BUILDKIT_PROGRESS) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=$(KANIDM_FEATURES)" \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: buildx/radiusd
buildx/radiusd: ## Build multi-arch radius docker images and push to docker hub
buildx/radiusd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull $(CONTAINER_BUILDX_ACTION) --platform $(CONTAINER_IMAGE_ARCH) \
		-f rlm_kanidm/Dockerfile \
		--progress $(BUILDKIT_PROGRESS) \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_VERSION) \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_EXT_VERSION) .

.PHONY: buildx
buildx: buildx/kanidmd buildx/kanidm_tools buildx/radiusd

.PHONE: cosign
cosign:
	$(COSIGN_CMD) $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION)
	# $(COSIGN_CMD) $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_EXT_VERSION)

.PHONY: build/kanidmd
build/kanidmd:	## Build the kanidmd docker image locally
build/kanidmd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f server/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=" \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: build/orca
build/orca:	## Build the orca docker image locally
build/orca:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f tools/orca/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/orca:$(CONTAINER_IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=$(KANIDM_FEATURES)" \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: build/radiusd
build/radiusd_rust:	## Build the radiusd docker image locally
build/radiusd_rust:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) \
		-f rlm_kanidm/Dockerfile \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_VERSION) .

.PHONY: build
build: build/kanidmd build/radiusd

.PHONY: test/kanidmd
test/kanidmd: ## Run cargo test in docker
test/kanidmd:
	@$(CONTAINER_TOOL) build \
		$(CONTAINER_TOOL_ARGS) -f server/Dockerfile \
		--target builder \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION)-builder \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .
	@$(CONTAINER_TOOL) run --rm $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION)-builder cargo test

.PHONY: test/radius/e2e
test/radius/e2e: ## Run end-to-end RADIUS integration tests
test/radius/e2e:
	./scripts/test_radius.sh

.PHONY: test
test:
	cargo test

.PHONY: precommit
precommit: ## all the usual test things
precommit: test codespell test/pykanidm doc/format

.PHONY: vendor
vendor: ## Vendor required crates
vendor:
	cargo vendor > cargo_vendor_config

.PHONY: vendor-prep
vendor-prep: vendor
	tar -cJf vendor.tar.xz vendor

.PHONY: install-tools
install-tools: ## install kanidm_tools in your local environment
install-tools:
	cargo install --path tools/cli --force

.PHONY: codespell
codespell: ## spell-check things.
codespell:
	codespell -c \
	-D .codespell_dictionary \
	--ignore-words .codespell_ignore \
	--skip='./target,./pykanidm/.venv,./pykanidm/.mypy_cache,./.mypy_cache,./pykanidm/uv.lock' \
	--skip='./book/*.js' \
	--skip='./book/book/*' \
	--skip='./book/src/images/*' \
	--skip='./docs/*,./.git' \
	--skip='*.svg' \
	--skip='*.br' \
	--skip='./rlm_python/mods-available/eap' \
	--skip='./server/lib/src/constants/system_config.rs' \
	--skip='./pykanidm/site'

.PHONY: test/pykanidm/pytest
test/pykanidm/pytest: ## python library testing
	cd pykanidm && \
	uv run pytest -vv

.PHONY: test/pykanidm/lint
test/pykanidm/lint: ## python library linting
	cd pykanidm && \
	uv run ruff check tests kanidm

.PHONY: test/pykanidm/typecheck
test/pykanidm/typecheck: ## python library type checking
	cd pykanidm && \
	uv run ty check tests kanidm \
		--ignore unused-type-ignore-comment

.PHONY: test/pykanidm
test/pykanidm: ## run the kanidm python module test suite (typecheck/lint/pytest)
test/pykanidm: test/pykanidm/pytest test/pykanidm/typecheck test/pykanidm/lint

.PHONY: test/pykanidm/coverage
test/pykanidm/coverage: ## run the Kanidm Python module test suite with coverage
	cd pykanidm && \
	uv run coverage run -m pytest && \
	uv run coverage html

########################################################################

.PHONY: doc
doc: ## Build the rust documentation locally
doc:
	cargo doc --document-private-items

.PHONY: doc/find
doc/find: ## Find all markdown files for docs
	@find . -type f  \
		-not -path './target/*' \
		-not -path './docs/*' \
		-not -path '*/node_modules/*' \
		-not -path '*/.venv/*' -not -path './vendor/*'\
		-not -path '*/.*/*' \
		-name '*.md'

.PHONY: doc/format
doc/format: ## Format docs and the Kanidm book
	make doc/find | xargs deno fmt --check $(MARKDOWN_FORMAT_ARGS)

.PHONY: doc/format/fix
doc/format/fix: ## Fix docs and the Kanidm book
	make doc/find | xargs  deno fmt  $(MARKDOWN_FORMAT_ARGS)

.PHONY: book
book: ## Build the Kanidm book
book:
	echo "Building rust docs"
	cargo doc --no-deps --quiet
	mdbook build book
	rm -rf ./docs/
	mv ./book/book/ ./docs/
	mkdir -p $(PWD)/docs/rustdoc/${BOOK_VERSION}/
	rsync -a --delete $(PWD)/target/doc/ $(PWD)/docs/rustdoc/${BOOK_VERSION}/

.PHONY: book_versioned
book_versioned:
	echo "Book version: ${BOOK_VERSION}"
	rm -rf ./target/doc
	git switch -c "${BOOK_VERSION}"
	git pull origin "${BOOK_VERSION}"
	cargo doc --no-deps --quiet
	mdbook build book
	rm -rf ./docs/
	mkdir -p ./docs
	mv ./book/book/ ./docs/${BOOK_VERSION}/
	mkdir -p ./docs/${BOOK_VERSION}/rustdoc/
	mv ./target/doc/* ./docs/${BOOK_VERSION}/rustdoc/
	git switch master

.PHONY: clean_book
clean_book:
	rm -rf ./docs

.PHONY: docs/pykanidm/build
docs/pykanidm/build: ## Build the mkdocs
docs/pykanidm/build:
	cd pykanidm && \
	uv run --group docs mkdocs build

.PHONY: docs/pykanidm/serve
docs/pykanidm/serve: ## Run the local mkdocs server
docs/pykanidm/serve:
	cd pykanidm && \
	uv run --group docs mkdocs serve

########################################################################

.PHONY: release/prep
prep:
	cargo outdated -R
	cargo audit

.PHONY: release/kanidm
release/kanidm: ## Build the Kanidm CLI - ensure you include the environment variable KANIDM_BUILD_PROFILE
	cargo build -p kanidm_tools --bin kanidm --release

.PHONY: release/kanidmd
release/kanidmd: ## Build the Kanidm daemon - ensure you include the environment variable KANIDM_BUILD_PROFILE
	cargo build -p daemon --bin kanidmd --release

.PHONY: release/kanidm-ssh
release/kanidm-ssh: ## Build the Kanidm SSH tools - ensure you include the environment variable KANIDM_BUILD_PROFILE
	cargo build --release \
		--bin kanidm_ssh_authorizedkeys \
		--bin kanidm_ssh_authorizedkeys_direct

.PHONY: release/kanidm-unixd
release/kanidm-unixd: ## Build the Kanidm UNIX tools - ensure you include the environment variable KANIDM_BUILD_PROFILE
release/kanidm-unixd:
	cargo build -p pam_kanidm --release
	cargo build -p nss_kanidm --release
	cargo build --features unix -p kanidm_unix_int --release \
		--bin kanidm_unixd \
		--bin kanidm_unixd_tasks \
		--bin kanidm-unix

# cert things

.PHONY: cert/clean
cert/clean: ## clean out the insecure cert bits
cert/clean:
	rm -f /tmp/kanidm/*.pem
	rm -f /tmp/kanidm/*.cnf
	rm -f /tmp/kanidm/*.csr
	rm -f /tmp/kanidm/ca.txt*
	rm -f /tmp/kanidm/ca.{cnf,srl,srl.old}


.PHONY: coverage
coverage: ## Run the coverage tests using cargo-tarpaulin
	cargo tarpaulin --out Html
	@echo "Coverage file at file://$(PWD)/tarpaulin-report.html"


.PHONY: coveralls
coveralls: ## Run cargo tarpaulin and upload to coveralls
coveralls:
	cargo tarpaulin --coveralls $(COVERALLS_REPO_TOKEN)
	@echo "Coveralls repo information is at https://coveralls.io/github/kanidm/kanidm"


.PHONY: eslint
eslint: ## Run eslint on the UI javascript things
eslint:
	@echo "################################"
	@echo "   Running eslint..."
	@echo "################################"
	cd server/core && find ./static -name '*js' -not -path '*/external/*' -exec pnpm exec eslint "{}" \;
	@echo "################################"
	@echo "Done!"

.PHONY: prettier
prettier: ## Run prettier on the UI javascript things and write back changes
prettier:
	@echo "   Running prettier..."
	cd server/core && pnpm run prettier:fix
	@echo "Done!"

.PHONY: publish
publish: ## Publish to crates.io
publish:
	cargo publish -p sketching
	cargo publish -p scim_proto
	cargo publish -p kanidm_build_profiles
	cargo publish -p kanidm_proto
	cargo publish -p kanidm_utils_users
	cargo publish -p kanidm_lib_file_permissions
	cargo publish -p kanidm_lib_crypto
	cargo publish -p kanidm_client
	cargo publish -p kanidm_tools

.PHONY: rust_container
rust_container: # Build and run a container based on the Linux rust base container, with our requirements included
rust_container:
	docker build --pull -t kanidm_rust -f scripts/Dockerfile.devcontainer .
	docker run \
		--rm -it \
		--name kanidm \
		--mount type=bind,source=$(PWD),target=/kanidm -w /kanidm kanidm_rust:latest
