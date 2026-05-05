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

data = requests.get(API + '/apis/batch/v1/jobs', headers=H, verify=CA, timeout=15).json()
rows = []
now = datetime.now(timezone.utc)
for it in data.get('items', []):
    ns = it['metadata']['namespace']
    name = it['metadata']['name']
    cronjob = next((o.get('name') for o in it['metadata'].get('ownerReferences', []) if o.get('kind')=='CronJob'), None)
    st = it.get('status', {})
    start = st.get('startTime')
    comp  = st.get('completionTime')
    dur = None
    if start and comp:
        a = datetime.fromisoformat(start.replace('Z','+00:00'))
        b = datetime.fromisoformat(comp.replace('Z','+00:00'))
        dur = int((b-a).total_seconds())
    status = 'failed' if st.get('failed', 0) else ('succeeded' if st.get('succeeded', 0) else 'running')
    rows.append((now, ns, name, cronjob, st.get('succeeded') or 0, st.get('failed') or 0,
                 start, comp, dur, status))
conn = psycopg2.connect(host=os.environ['PGHOST'], user=os.environ['PGUSER'],
                        dbname=os.environ['PGDATABASE'], password=os.environ['PGPASSWORD'])
with conn, conn.cursor() as cur:
    cur.executemany(
        "INSERT INTO k8s_jobs (time, namespace, name, cronjob, succeeded, failed, "
        "  start_time, completion_time, duration_seconds, status) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", rows)
print(f'inserted {len(rows)} k8s_jobs rows')
PY
