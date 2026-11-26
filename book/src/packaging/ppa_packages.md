# Kanidm PPA Packages

> [!NOTE]
> These are not supported in the main repo, please raise issues in the
> [kanidm/kanidm_ppa_automation](https://github.com/kanidm/kanidm_ppa_automation) repository, and understand that it is
> a community-supported effort, rather than by the core Kanidm project.

- The Kanidm PPA repository contains Debian & Ubuntu packages built from the
  [main Kanidm repository](https://github.com/kanidm/kanidm). For more information on version support,
  see the [Distribution support policy](https://github.com/kanidm/kanidm_ppa_automation/#distribution-support-policy).

- Please note that while the spirit of the commands below should also work on other Debian-based distributions, the
  codename detection will not work and you will need to manually choose which distribution is the closest to yours. The
  methods for adding repositories may also vary, for example Pop OS, requires an altered setup in line with their
  [instructions](https://support.system76.com/articles/ppa-third-party/).

## Adding it to your system

Make sure you have a “trusted GPG” directory for storing signing keys.

```bash
sudo mkdir -p /etc/apt/trusted.gpg.d/
```

Download the Kanidm PPA GPG public key.

```bash
curl -s "https://kanidm.github.io/kanidm_ppa/kanidm_ppa.asc" \
    | sudo tee /etc/apt/trusted.gpg.d/kanidm_ppa.asc >/dev/null
```

Add the Kanidm PPA to your local APT configuration, with autodetection of Ubuntu vs. Debian.

```bash
curl -s "https://kanidm.github.io/kanidm_ppa/kanidm_ppa.list" \
    | grep $(awk -F= '/^VERSION_CODENAME=/ {print $2}' /etc/os-release) \
    | sudo tee /etc/apt/sources.list.d/kanidm_ppa.list
```

Update your local package cache.

```bash
sudo apt update
```

## Listing Packages

Use `apt search` to list the packages available:

```bash
apt search kanidm
```
