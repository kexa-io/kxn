# Kubernetes right-sizing with `kxn recommend`

`kxn recommend` compares what containers actually use with what they request and proposes new requests per workload — the same idea as KRR, Goldilocks or the Datadog / Splunk "workload optimization" views, but as a single command whose output can go straight to a ticket, a PDF or an LLM.

```bash
kxn recommend kubernetes://in-cluster                              # table on stdout
kxn recommend -n payments --window 7d --format json -o rec.json    # one namespace, 7 days
kxn recommend --samples 10 --every 30s --history none --format toon # no DB: 10 live samples, TOON output
kxn recommend --format pdf -o rightsizing.pdf                       # printable report
```

## Where the usage comes from

1. **History (preferred).** A PostgreSQL URL given with `--history`, or the first postgres `[[save]]` of `kxn.toml`. Two schemas are recognised:
   - the flat `pod_resource` table created by the `kxn-stack` chart (one row per container per minute);
   - kxn's own `resources` table written by `kxn watch` + `[[save]]` (`pod_resource` / `pod_efficiency` objects).
   Percentile and max are computed in SQL over `--window` (default `14d`), so a month of minute-level samples stays cheap.
2. **Live sampling (fallback).** Without history, `--samples N --every D` gathers `pod_efficiency` N times. One sample only reflects the current minute — say so in the report you hand over.

The current requests/limits, owning workload and replica count always come from a live `pod_efficiency` gather, so containers that disappeared from the cluster are never listed.

## Policy (KRR-style)

| Quantity | Rule | Flag |
|---|---|---|
| CPU request | p95 of observed usage, rounded up to 5 m, minimum 10 m | `--cpu-percentile 95` |
| Memory request | max observed + 15 %, rounded up to 8 Mi, minimum 16 Mi | `--memory-headroom 15` |
| Memory limit | = memory request | — |
| CPU limit | untouched (kxn does not recommend CPU limits) | — |
| Listing threshold | hide workloads whose change is below 10 % of the current request | `--min-change 10` (0 = list all) |

Replicas of one workload are merged: the recommendation is the worst case across pods, and the cluster effect in the summary is the per-replica change multiplied by the replica count.

Actions: `reduce`, `increase`, `rebalance` (one resource up, the other down), `set` (no request today), `keep` (hidden unless `--min-change 0`).

## Output formats

- `text` — fixed-width table plus summary and policy.
- `json` — `{ summary, recommendations[], meta }`; every recommendation row is flat (primitives only).
- `toon` — [TOON](https://github.com/toon-format/toon) encoding of the same document: the 100-row report above is ~4.5× smaller than the JSON, handy for an LLM prompt ("apply these, generate the kustomize patches").
- `pdf` — A4 landscape report rendered by kxn itself (no external tool), `--output` defaults to `./kxn-recommend.pdf`.

Row fields: `namespace, kind, workload, container, replicas, samples, source (history|live), action, cpu_request_m, cpu_limit_m, cpu_p_m, cpu_max_m, cpu_rec_request_m, cpu_change_m, mem_request_mib, mem_limit_mib, mem_max_mib, mem_rec_request_mib, mem_rec_limit_mib, mem_change_mib`.

## Feeding an LLM

```bash
kxn recommend --format toon -o rec.toon
# then, in your agent prompt:
#   "Here is a kxn right-sizing report (TOON). Produce a Kustomize patch per workload
#    whose action is reduce or set, keep CPU limits as they are."
```

The same data is available continuously through the `pod_efficiency` object (rules in `rules/kubernetes-resources.toml`, gauges with `kxn watch --metrics-resources`).
