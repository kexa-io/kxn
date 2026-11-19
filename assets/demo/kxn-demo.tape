# kxn demo — rendered with VHS (https://github.com/charmbracelet/vhs).
# Prerequisites and the exact podman/docker command: see assets/demo/README.md.
# Everything on screen is real output from kxn against a local kind cluster.

Output out/kxn-demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 680
Set Padding 18
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 18ms
Set Framerate 15
Set CursorBlink false

# ---------- hidden setup ----------
Hide
Type "source /demo/work/demo.env && cd /demo && export DB=postgresql://postgres:demo@localhost:$PG_PORT/kxn" Enter
Type "export PS1='\[\e[1;35m\]kxn-demo\[\e[0m\] \[\e[1;36m\]$\[\e[0m\] '" Enter
Type "psql -q $DB -c 'drop schema public cascade; create schema public' >/dev/null 2>&1; clear" Enter
Sleep 1s
Show

# ---------- 1. Kubernetes ----------
Type "# 1/5  Kubernetes: CIS benchmark on a live kind cluster (read-only ServiceAccount)" Enter
Sleep 300ms
Type "kxn kubernetes://kind -R rules/kubernetes-cis.toml -o compact" Enter
Wait /kxn-demo \$/
Sleep 4s

# ---------- 2. Database ----------
Hide
Type "clear" Enter
Show
Type "# 2/5  Databases: PostgreSQL CIS + DBA checks (MySQL, MongoDB, Oracle too)" Enter
Sleep 300ms
Type "kxn postgresql://postgres:demo@localhost:25432?sslmode=disable -o compact | head -14" Enter
Wait /kxn-demo \$/
Sleep 4s

# ---------- 3. CVEs ----------
Hide
Type "clear" Enter
Show
Type "# 3/5  CVEs: installed packages over SSH vs local NVD + KEV + EPSS + distro trackers" Enter
Sleep 300ms
Type "kxn ssh://root:demo@localhost:22222 -R rules/packages-cve.toml" Enter
Wait@30s /kxn-demo \$/
Sleep 3.5s
Type "kxn list-providers | grep -E '^  (aws|azure|gcp|github) '    # same CLI for the cloud" Enter
Wait /kxn-demo \$/
Sleep 2.5s

# ---------- 4. Logs ----------
Hide
Type "clear" Enter
Show
Type "# 4/5  Logs: poll pod logs, keep errors, ship them to the [[save]] backends (PostgreSQL)" Enter
Sleep 300ms
Type "kxn logs kubernetes://kind --level error --interval 3 --config-file kxn.toml -o json | jq -c '{at: .timestamp[11:19], errors, pods: (.by_source | length)}'" Enter
Sleep 8s
Ctrl+C
Sleep 300ms
Hide
Type "clear" Enter
Show

# ---------- 5. Metrics + storage ----------
Type "# 5/5  Continuous mode: Prometheus metrics + every result stored in PostgreSQL" Enter
Sleep 300ms
Type "kxn watch --config-file kxn.toml --metrics-port 9090 &> watch.log &" Enter
Sleep 4s
Type "curl -s localhost:9090/metrics | grep -E '^kxn_rules_(total|failed)'" Enter
Wait /kxn-demo \$/
Sleep 3s
Type `psql $DB -c "select target, count(*) as violations from scans group by 1"` Enter
Wait /kxn-demo \$/
Sleep 2.5s
Type `psql $DB -c "select unit, message from logs where unit='payment-worker' order by id desc limit 3"` Enter
Wait /kxn-demo \$/
Sleep 5s
