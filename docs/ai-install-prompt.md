# Prompt: install kxn in a Kubernetes cluster with an AI assistant

Copy the prompt below into an AI assistant (Claude, ChatGPT, etc.) to install kxn in read-only mode. The assistant produces YAML files ready to apply, then the verification commands.

Requires a kxn release that includes the `[rules]`-optional and `-R` fixes for `watch` (PR #200). Check the version with `kxn --version`.

---

```text
You install kxn (kexa/kxn) in a Kubernetes cluster, read-only.

Constraints:
- Image pinned to an exact tag: docker.io/kexa/kxn:v0.54.0. Never use :latest.
- Dedicated ServiceAccount, bound only to the built-in ClusterRole "view". No write permission.
- Start from deploy/kubernetes/kxn-watch-readonly.yaml in the kxn repository. Change only the namespace, the image tag and the targets. Do not write the manifests from scratch.
- Never print a secret in the output.

Steps, in order:
1. Namespace and ServiceAccount, with a ClusterRoleBinding to "view".
2. Rules: an initContainer runs `kxn rules pull --dir /rules` into a shared emptyDir volume. The rules are not fetched at runtime.
3. kxn.toml: one [[targets]] entry with uri = "kubernetes://in-cluster". "provider" is optional when "uri" is set. A [rules] section is optional.
4. Run: kxn -c /etc/kxn/kxn.toml watch -R /rules --metrics-port 9090 --interval 300
5. Verify:
   - The log shows "rules=N" with N > 0.
   - The log shows "#1 OK" or "#1 FAIL" with the number of checks.
   - curl with the bearer token from the kxn-metrics secret (never print it) on http://<service>:9090/metrics returns kxn_rules_total, kxn_rules_passed, kxn_rules_failed. Without the token the answer is 401.

If the output says:
- "No rules loaded": the initContainer did not run or wrote to another path. Check its logs and the -R value. Do not change the rules.
- "no provider specified": add uri = "kubernetes://in-cluster" to the target.
- "forbidden" from the Kubernetes API: the ServiceAccount is missing the ClusterRoleBinding to "view". Do not add write permissions to fix it.
- Port 9090 closed: `--metrics-port` is an option of `watch` only. `kxn monitor` does not expose metrics.

Return the YAML files ready to apply, then the list of verification commands.
```

---

Metric names: see [metrics.md](metrics.md). Manifest: [`deploy/kubernetes/kxn-watch-readonly.yaml`](../deploy/kubernetes/kxn-watch-readonly.yaml).
