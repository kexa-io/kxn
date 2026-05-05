set -e
pip install --quiet psycopg2-binary requests urllib3
python3 - <<'PY'
import os, re, json, requests, urllib3, psycopg2
urllib3.disable_warnings()
T = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()
CA = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
API = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ['KUBERNETES_SERVICE_PORT']}"
H = {'Authorization': f'Bearer {T}'}
pods_data = requests.get(API + '/api/v1/pods', headers=H, verify=CA, timeout=15).json()
rows = []
for it in pods_data.get('items', [])[:80]:
    ns = it['metadata']['namespace']
    pod = it['metadata']['name']
    node = (it.get('spec', {}) or {}).get('nodeName', '')
    for c in (it.get('spec', {}).get('containers') or []):
        cname = c['name']
        try:
            r = requests.get(f"{API}/api/v1/namespaces/{ns}/pods/{pod}/log",
                params={'container': cname, 'sinceSeconds': 70, 'tailLines': 100, 'timestamps': 'true'},
                headers=H, verify=CA, timeout=10)
            if r.status_code != 200: continue
            for line in r.text.splitlines():
                m = re.match(r'^(\S+)\s+(.*)$', line)
                if not m: continue
                ts, msg = m.group(1), m.group(2)
                low = msg.lower()
                if 'fatal' in low or 'panic' in low: lvl = 'fatal'
                elif 'error' in low or 'err ' in low: lvl = 'error'
                elif 'warn' in low: lvl = 'warning'
                else: lvl = 'info'
                tags = json.dumps({'namespace': ns, 'pod': pod, 'node': node, 'container': cname})
                rows.append((ts, f"{ns}/{pod}", cname, lvl, msg[:1000], pod, cname, tags))
        except Exception:
            pass
conn = psycopg2.connect(host=os.environ['PGHOST'], user=os.environ['PGUSER'],
                        dbname=os.environ['PGDATABASE'], password=os.environ['PGPASSWORD'])
with conn, conn.cursor() as cur:
    cur.executemany("INSERT INTO logs (time, target, source, level, message, host, unit, tags) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)", rows)
print(f'inserted {len(rows)} log rows')
PY
