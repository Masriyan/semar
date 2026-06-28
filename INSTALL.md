# Installing SEMAR

SEMAR is a single, statically-linked Go binary with no runtime dependencies. It
runs on Linux, macOS, and Windows (amd64 and arm64).

- [Requirements](#requirements)
- [Method 1 — Build from source (recommended for now)](#method-1--build-from-source)
- [Method 2 — go install](#method-2--go-install)
- [Method 3 — Prebuilt release binaries](#method-3--prebuilt-release-binaries)
- [Method 4 — Docker](#method-4--docker)
- [Verifying the install](#verifying-the-install)
- [Shell completion](#shell-completion)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

---

## Requirements

| To... | You need |
|-------|----------|
| Build from source | Go **1.22+** |
| Run a prebuilt binary | Nothing — it is static |
| CVE lookups (`--cve-lookup`) | Outbound HTTPS to `api.osv.dev` |
| PDF/HTML reports | Nothing extra — generation is built in |

Check your Go version:

```bash
go version   # go1.22 or newer
```

---

## Method 1 — Build from source

```bash
git clone https://github.com/masriyan/semar.git
cd semar
make build            # outputs ./bin/semar
./bin/semar version
```

Install it onto your `PATH`:

```bash
make install          # copies bin/semar -> /usr/local/bin/semar (may need sudo)
```

Or build manually with version metadata baked in:

```bash
go build -ldflags "-X main.version=v0.1.0 -s -w" -o bin/semar .
```

### Cross-compiling

```bash
make build-all        # builds linux/darwin/windows × amd64/arm64 into dist/
```

---

## Method 2 — go install

```bash
go install github.com/masriyan/semar@latest
```

The binary lands in `$(go env GOPATH)/bin`. Ensure that directory is on your
`PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
semar version
```

> Note: `go install` does not embed the `git describe` version; the binary will
> report its built-in default. Use `make build` if you need precise version
> metadata.

---

## Method 3 — Prebuilt release binaries

Releases are produced by GoReleaser and published at
**[github.com/masriyan/semar/releases](https://github.com/masriyan/semar/releases)**.

```bash
# Example: Linux amd64
curl -L -o semar.tar.gz \
  https://github.com/masriyan/semar/releases/latest/download/semar_linux_amd64.tar.gz
tar -xzf semar.tar.gz
chmod +x semar
sudo mv semar /usr/local/bin/

# Verify the checksum (recommended)
curl -L -O https://github.com/masriyan/semar/releases/latest/download/checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

Each release also ships an **SBOM** (Software Bill of Materials) alongside the
archives.

---

## Method 4 — Docker

A minimal image (build from the repo):

```dockerfile
# Dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN make build

FROM gcr.io/distroless/static-debian12
COPY --from=build /src/bin/semar /semar
ENTRYPOINT ["/semar"]
```

```bash
docker build -t semar:local .
docker run --rm -v "$PWD:/scan" semar:local audit --target /scan --no-color
```

> Mount the target read-only for extra peace of mind — SEMAR never writes, but
> `-v "$PWD:/scan:ro"` makes that guarantee enforced by the kernel.

---

## Verifying the install

```bash
semar version
```

You should see the SEMAR banner, the version, commit, build date, and the list
of supported agents and modules.

---

## Shell completion

SEMAR is built on Cobra, which generates completion scripts:

```bash
# bash
semar completion bash | sudo tee /etc/bash_completion.d/semar > /dev/null

# zsh
semar completion zsh > "${fpath[1]}/_semar"

# fish
semar completion fish > ~/.config/fish/completions/semar.fish

# PowerShell
semar completion powershell | Out-String | Invoke-Expression
```

---

## Upgrading

- **Source:** `git pull && make build`
- **go install:** `go install github.com/masriyan/semar@latest`
- **Binaries:** download the new release and replace the binary

Check [CHANGELOG.md](CHANGELOG.md) before upgrading across minor versions — exit
code semantics are a stable contract and will never change in a minor release.

---

## Uninstalling

```bash
sudo rm /usr/local/bin/semar          # if installed to PATH
# or remove the go install binary:
rm "$(go env GOPATH)/bin/semar"
```

SEMAR stores no global state, caches, or config outside files you explicitly
create (e.g. `.semar.yml`, baselines, report outputs).

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `command not found: semar` | The binary isn't on your `PATH`. See Method 1/2. |
| `go: requires go >= 1.22` | Upgrade Go. |
| Colors look garbled | Your terminal lacks ANSI/UTF-8 support — run with `--no-color`. |
| Banner boxes misaligned | Use a monospace, UTF-8 font (the banner uses box-drawing characters). |
| `--cve-lookup` hangs/fails | Outbound HTTPS to `api.osv.dev` is blocked; omit the flag for offline scans. |
| PDF/HTML looks wrong in a viewer | Open the HTML in a modern browser; open the PDF in any standard reader. |

Still stuck? Open an issue at
**[github.com/masriyan/semar/issues](https://github.com/masriyan/semar/issues)**.
