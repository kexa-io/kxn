set -e
pip install --quiet psycopg2-binary requests urllib3
python3 - <<'PY'
import os, requests, urllib3, psycopg2
from datetime import datetime, timezone
urllib3.disable_warnings()
T = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()
CA = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
API = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ['KUBERNETES_SERVICE_PORT']}"
H = {'Authorization': f'Bearer {T}'}

def k(p):
    r = requests.get(API+p, headers=H, verify=CA, timeout=10); r.raise_for_status(); return r.json()

def cpu_to_m(s):
    if s.endswith('n'): return float(s[:-1])/1_000_000
    if s.endswith('u'): return float(s[:-1])/1_000
    if s.endswith('m'): return float(s[:-1])
    return float(s)*1000
def mem_to_mib(s):
    n = float(''.join(c for c in s if c.isdigit() or c=='.'))
    if 'Ki' in s: return n/1024
    if 'Mi' in s: return n
    if 'Gi' in s: return n*1024
    return n / (1024*1024)

data = k('/apis/metrics.k8s.io/v1beta1/pods')
rows = []
now = datetime.now(timezone.utc)
for it in data.get('items', []):
    ns = it['metadata']['namespace']
    pod = it['metadata']['name']
    for c in it.get('containers', []):
        rows.append((now, ns, pod, c['name'],
                     cpu_to_m(c['usage']['cpu']),
                     mem_to_mib(c['usage']['memory'])))
conn = psycopg2.connect(host=os.environ['PGHOST'], user=os.environ['PGUSER'],
                        dbname=os.environ['PGDATABASE'], password=os.environ['PGPASSWORD'])
with conn, conn.cursor() as cur:
    cur.executemany(
        "INSERT INTO pod_resource (time, namespace, pod, container, cpu_millicores, memory_mib) "
        "VALUES (%s, %s, %s, %s, %s, %s)", rows)
print(f'inserted {len(rows)} pod_resource rows')
PY
