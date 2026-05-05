set -e
pip install --quiet psycopg2-binary requests urllib3
python3 - <<'PY'
import json, os, ssl
from datetime import datetime, timezone
import psycopg2, requests, urllib3
urllib3.disable_warnings()

TOKEN = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()
CA = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
API = f'https://{os.environ["KUBERNETES_SERVICE_HOST"]}:{os.environ["KUBERNETES_SERVICE_PORT"]}'
H = {'Authorization': f'Bearer {TOKEN}'}

def k8s_get(path):
    r = requests.get(API + path, headers=H, verify=CA, timeout=10)
    r.raise_for_status()
    return r.json()

# 1. List nodes.
nodes = [n['metadata']['name'] for n in k8s_get('/api/v1/nodes')['items']]
print(f'discovered {len(nodes)} nodes')

# 2. Build a (claim_uid)->(namespace, pvc_name, storage_class) map by
# cross-referencing PVCs and PVs. The kubelet stats expose volumes
# by claim_uid, not name, so this lookup is required.
pvcs = {}
for pvc in k8s_get('/api/v1/persistentvolumeclaims')['items']:
    uid = pvc['metadata']['uid']
    pvcs[uid] = {
        'namespace': pvc['metadata']['namespace'],
        'name': pvc['metadata']['name'],
        'storageClass': pvc['spec'].get('storageClassName'),
    }
print(f'mapped {len(pvcs)} PVCs')

rows = []
now = datetime.now(timezone.utc)
for node in nodes:
    try:
        stats = k8s_get(f'/api/v1/nodes/{node}/proxy/stats/summary')
    except Exception as e:
        print(f'node {node}: stats failed ({e}), skipping')
        continue

    # Node root + image filesystem
    fs = stats.get('node', {}).get('fs', {}) or {}
    if fs:
        rows.append((now, node, 'node_root', None, None, None,
                     fs.get('capacityBytes'), fs.get('usedBytes'),
                     fs.get('availableBytes')))
    img_fs = stats.get('node', {}).get('runtime', {}).get('imageFs', {}) or {}
    if img_fs:
        rows.append((now, node, 'node_image', None, None, None,
                     img_fs.get('capacityBytes'), img_fs.get('usedBytes'),
                     img_fs.get('availableBytes')))

    # Per-pod volumes (PVCs surface as `pvcRef`)
    for pod in stats.get('pods', []) or []:
        for vol in pod.get('volume', []) or []:
            pvc_ref = vol.get('pvcRef')
            if not pvc_ref:
                continue
            ns = pvc_ref.get('namespace')
            name = pvc_ref.get('name')
            # Look up storage class by (ns,name).
            sc = None
            for v in pvcs.values():
                if v['namespace'] == ns and v['name'] == name:
                    sc = v['storageClass']
                    break
            rows.append((now, node, 'pvc', ns, name, sc,
                         vol.get('capacityBytes'), vol.get('usedBytes'),
                         vol.get('availableBytes')))

print(f'collected {len(rows)} disk samples')

conn = psycopg2.connect(
    host=os.environ['PGHOST'], user=os.environ['PGUSER'],
    dbname=os.environ['PGDATABASE'], password=os.environ['PGPASSWORD'],
)
with conn, conn.cursor() as cur:
    cur.executemany(
        "INSERT INTO disk_usage (time, node, resource_kind, namespace, pvc_name, "
        "  storage_class, capacity_bytes, used_bytes, available_bytes) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        rows,
    )
print(f'inserted {len(rows)} rows')
PY
