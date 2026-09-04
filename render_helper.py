import sys
import os
import requests
import json

API_KEY = os.getenv('RENDER_API_KEY', 'rnd_RerUVPbRk8WYeslcVKxvc2ayDQWO')
HEADERS = {
    'Authorization': f'Bearer {API_KEY}',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

def list_services():
    r = requests.get('https://api.render.com/v1/services', headers=HEADERS)
    if r.status_code != 200:
        print('Error:', r.status_code, r.text)
        return []
    services = r.json()
    print(f'Total Services in Account: {len(services)}')
    for s in services:
        srv = s.get('service', {})
        name = srv.get('name')
        sid = srv.get('id')
        stype = srv.get('type')
        url = srv.get('serviceDetails', {}).get('url')
        print(f"- {name} (ID: {sid}, Type: {stype}, URL: {url})")
    return services

def set_env_var(service_id, key, value):
    # Fetch existing
    r = requests.get(f'https://api.render.com/v1/services/{service_id}/env-vars', headers=HEADERS)
    env_vars = r.json() if r.status_code == 200 else []
    
    # Update or add
    found = False
    new_vars = []
    for ev in env_vars:
        ev_data = ev.get('envVar', ev)
        if ev_data.get('key') == key:
            new_vars.append({'key': key, 'value': value})
            found = True
        else:
            new_vars.append({'key': ev_data.get('key'), 'value': ev_data.get('value')})
    if not found:
        new_vars.append({'key': key, 'value': value})

    put_res = requests.put(f'https://api.render.com/v1/services/{service_id}/env-vars', headers=HEADERS, json=new_vars)
    print(f'Set {key}={value} on {service_id}: Status {put_res.status_code}')
    return put_res.status_code in [200, 201]

def trigger_deploy(service_id):
    r = requests.post(f'https://api.render.com/v1/services/{service_id}/deploys', headers=HEADERS, json={'clearCache': 'do_not_clear'})
    print(f'Trigger Deploy on {service_id}: Status {r.status_code}')
    if r.status_code == 201:
        deploy = r.json()
        dep_id = deploy.get('id')
        dep_status = deploy.get('status')
        print(f'Deploy ID: {dep_id}, Status: {dep_status}')
    else:
        print('Response:', r.text)

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'list'
    if cmd == 'list':
        list_services()
    elif cmd == 'set-env' and len(sys.argv) >= 4:
        set_env_var(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == 'deploy' and len(sys.argv) >= 3:
        trigger_deploy(sys.argv[2])
    else:
        print('Usage: python render_helper.py [list | set-env <serviceId> <key> <val> | deploy <serviceId>]')
