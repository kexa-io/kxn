# kxn demo GIF

`kxn-demo.gif` is rendered from `kxn-demo.tape` with [VHS](https://github.com/charmbracelet/vhs).
Every line on screen is real output from `kxn` against a local [kind](https://kind.sigs.k8s.io) cluster.

The demo covers Kubernetes CIS checks, a PostgreSQL scan, a package CVE scan over SSH,
Kubernetes log collection, and `kxn watch` with Prometheus metrics and PostgreSQL storage.

## 1. Cluster and targets

```bash
export OUT=$PWD/demo-work                    # env file, CA, kxn.toml land here
# export KIND_EXPERIMENTAL_PROVIDER=podman   # if you use podman instead of docker
./assets/demo/setup-kind.sh
```

The script creates the `kxn-demo` kind cluster and the `demo` namespace with the following workloads:

- `legacy-web`: a deliberately weak Deployment (privileged, `:latest`, no limits).
- `payment-worker`: a pod that logs `ERROR` lines.
- `crashy`: a pod in a crash loop.
- `postgres`: PostgreSQL 16, also the `[[save]]` backend.
- `legacy-vm`: an old Debian snapshot running sshd.

The script also creates a read-only `kxn-reader` ServiceAccount.
kxn does not read kubeconfig, so the script writes `K8S_API_URL`, `K8S_TOKEN` and `K8S_CA_FILE` to `$OUT/demo.env`.
Finally, it port-forwards PostgreSQL to `localhost:25432` and SSH to `localhost:22222` and writes `$OUT/kxn.toml`.

## 2. CVE database

The CVE scan needs the local CVE database. `kxn cve-update` syncs NVD, KEV, EPSS and the distro trackers. The first sync takes a few minutes.

```bash
mkdir -p "$OUT/cache"
XDG_CACHE_HOME="$OUT/cache" kxn cve-update
```

## 3. Render

The tape expects `kxn` in `PATH`, the repo `rules/` at `/demo/rules`, `kxn.toml` at `/demo/kxn.toml`, and the env file at `/demo/work/demo.env`. It also needs `psql`, `curl` and `jq`.
To render with the VHS image plus those tools:

```bash
cat > /tmp/Containerfile.vhs <<'EOF2'
FROM ghcr.io/charmbracelet/vhs
RUN apt-get update && apt-get install -y --no-install-recommends curl postgresql-client jq \
 && rm -rf /var/lib/apt/lists/*
EOF2
podman build -t kxn-vhs -f /tmp/Containerfile.vhs /tmp      # or docker build

mkdir -p "$OUT/run" "$OUT/gif"
podman run --rm --network host \
  -v "$(command -v kxn)":/usr/local/bin/kxn:ro \
  -v "$OUT/run":/demo \
  -v "$PWD/rules":/demo/rules:ro \
  -v "$OUT":/demo/work:ro \
  -v "$OUT":"$OUT":ro \
  -v "$OUT/kxn.toml":/demo/kxn.toml:ro \
  -v "$OUT/cache":/root/.cache \
  -v "$PWD/assets/demo/kxn-demo.tape":/vhs/kxn-demo.tape:ro \
  -v "$OUT/gif":/vhs/out \
  kxn-vhs kxn-demo.tape
cp "$OUT/gif/kxn-demo.gif" assets/demo/kxn-demo.gif
```

The `kxn` binary must be a glibc Linux x86_64 build, because the VHS image runs Debian.
`--network host` lets the container reach the kind API server and the port-forwards.
The `$OUT:$OUT` mount keeps the `K8S_CA_FILE` path from `demo.env` valid inside the container.

## 4. Clean up

```bash
./assets/demo/setup-kind.sh down
```
