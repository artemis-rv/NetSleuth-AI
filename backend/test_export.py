"""Test the live export endpoint with correct auth."""
import urllib.request, urllib.parse, json

# Login as admin_user
login_data = urllib.parse.urlencode({'username': 'admin_user', 'password': 'password'}).encode()
req = urllib.request.Request(
    'http://127.0.0.1:8080/api/v1/auth/login',
    data=login_data,
    headers={'Content-Type': 'application/x-www-form-urlencoded'}
)
with urllib.request.urlopen(req) as resp:
    result = json.loads(resp.read())
    token = result.get('access_token')
    print('Logged in OK, role=administrator')

report_id = 'f8462d18-9cbb-4409-b537-8a158d1035c2'

for fmt in ['json', 'txt', 'pdf']:
    try:
        req3 = urllib.request.Request(
            f'http://127.0.0.1:8080/api/v1/reports/{report_id}/export?format={fmt}',
            headers={'Authorization': f'Bearer {token}'}
        )
        with urllib.request.urlopen(req3) as resp3:
            body = resp3.read()
            print(f'Export {fmt.upper()}: OK - {len(body)} bytes, type={resp3.headers.get("content-type")}')
    except urllib.error.HTTPError as e:
        body_raw = e.read()
        try:
            body = json.loads(body_raw)
            print(f'Export {fmt.upper()}: FAILED {e.code} - {json.dumps(body, indent=2)[:600]}')
        except Exception:
            print(f'Export {fmt.upper()}: FAILED {e.code} - {body_raw[:400]}')
