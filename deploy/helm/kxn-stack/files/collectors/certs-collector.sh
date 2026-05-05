set -e
pip install --quiet psycopg2-binary requests urllib3 cryptography
python3 - <<'PY'
import os, base64, requests, urllib3, psycopg2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
urllib3.disable_warnings()
T = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()
CA = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
API = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ['KUBERNETES_SERVICE_PORT']}"
H = {'Authorization': f'Bearer {T}'}

data = requests.get(API + '/api/v1/secrets?fieldSelector=type=kubernetes.io/tls',
                    headers=H, verify=CA, timeout=15).json()
rows = []
now = datetime.now(timezone.utc)
for it in data.get('items', []):
    ns = it['metadata']['namespace']
    name = it['metadata']['name']
    d = it.get('data', {}).get('tls.crt')
    if not d: continue
    try:
        pem = base64.b64decode(d)
        # PEM bundle may have multiple certs; take the leaf (first).
        # cryptography>=39 only accepts one positional arg.
        cert = x509.load_pem_x509_certificates(pem)[0]
    except Exception as e:
        print(f'parse {ns}/{name} failed: {e}'); continue
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = ''
    try:
        san = ','.join(s.value for s in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except Exception:
        san = ''
    try:
        issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        issuer = ''
    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).days
    rows.append((now, ns, name, cn[:255], san[:8000], issuer[:255], not_after, days_left))
conn = psycopg2.connect(host=os.environ['PGHOST'], user=os.environ['PGUSER'],
                        dbname=os.environ['PGDATABASE'], password=os.environ['PGPASSWORD'])
with conn, conn.cursor() as cur:
    cur.executemany(
        "INSERT INTO tls_certs (time, namespace, secret_name, common_name, san, issuer, not_after, days_left) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", rows)
print(f'inserted {len(rows)} tls_certs rows')
PY
