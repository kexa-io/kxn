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

ns_list = [n['metadata']['name'] for n in requests.get(API+'/api/v1/namespaces', headers=H, verify=CA, timeout=10).json()['items']]
np_list = requests.get(API+'/apis/networking.k8s.io/v1/networkpolicies', headers=H, verify=CA, timeout=10).json()['items']

per_ns = {ns: [] for ns in ns_list}
for np in np_list:
    ns = np['metadata']['namespace']
    per_ns.setdefault(ns, []).append(np)

rows = []
now = datetime.now(timezone.utc)
for ns, nps in per_ns.items():
    # default-deny = at least one policy with empty podSelector AND empty policyTypes ingress entry
    has_dd = any(
        np.get('spec', {}).get('podSelector', {}) == {} and
        'Ingress' in (np.get('spec', {}).get('policyTypes') or [])
        for np in nps
    )
    rows.append((now, ns, len(nps), has_dd))
conn = psycopg2.connect(host=os.environ['PGHOST'], user=os.environ['PGUSER'],
                        dbname=os.environ['PGDATABASE'], password=os.environ['PGPASSWORD'])
with conn, conn.cursor() as cur:
    cur.executemany(
        "INSERT INTO netpol_coverage (time, namespace, netpol_count, has_default_deny) "
        "VALUES (%s, %s, %s, %s)", rows)
print(f'inserted {len(rows)} netpol_coverage rows')
PY
