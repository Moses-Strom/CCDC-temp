#!/usr/bin/env python3
"""Sandbox-only regression tests for ccdc-baseline-v2.sh; never touches host /etc or /opt."""
import hashlib, json, os, pathlib, subprocess, tempfile

SCRIPT = pathlib.Path(__file__).with_name('ccdc-baseline-v2.sh')
passed=0

def command(root, *args, expected):
    cp = subprocess.run(['bash', str(SCRIPT), args[0], '--lab-root', str(root), *args[1:]],
                        capture_output=True, text=True, timeout=30)
    assert cp.returncode == expected, (cp.args, cp.returncode, expected, cp.stdout, cp.stderr)
    return cp

def file(root, rel, data, mode=0o644):
    p = root / rel.lstrip('/')
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    p.chmod(mode)
    return p

def assert_case(cond, label):
    global passed
    assert cond, label
    passed += 1
    print(f'PASS [{passed:02d}]: {label}')

with tempfile.TemporaryDirectory(prefix='ccdc-v2-tests-') as d:
    r = pathlib.Path(d)
    file(r, '/etc/systemd/system/splunk.service', '[Service]\nExecStart=/bin/true\n')
    ssh = file(r, '/etc/ssh/sshd_config', 'Port 22\nPermitRootLogin no\n')
    inputs = file(r, '/opt/splunk/etc/system/local/inputs.conf', '[splunktcp://9997]\ndisabled=0\n')
    file(r, '/usr/local/bin/team script.sh', '#!/bin/sh\necho safe\n', 0o755)
    secret = file(r, '/etc/shadow', 'root:old-secret:1::::::\n',0o600)
    authorized = file(r, '/root/.ssh/authorized_keys', 'ssh-ed25519 initial\n',0o600)
    newline = file(r, '/etc/systemd/system/new\nline.service', '[Service]\nExecStart=/bin/true\n')
    oversized = file(r,'/etc/systemd/system/huge.service',b'X'* (3*1024*1024+1))
    base = command(r,'--baseline',expected=0)
    assert_case('BASELINE CREATED' in base.stdout, 'Atomic baseline created')
    assert_case(command(r,'--baseline',expected=2).returncode==2,'Baseline overwrite refused')
    clean = command(r,'--check',expected=0)
    assert_case('added=0, missing=0, modified=0' in clean.stdout,'Unchanged baseline checks clean')
    manifest=json.loads((r/'.ccdc-v2-state/manifest.json').read_text())
    assert_case(manifest['files']['/etc/shadow'].get('copy') is None, 'Linux shadow hash-only (not restorable)')
    assert_case(manifest['files']['/root/.ssh/authorized_keys'].get('copy') is None,'Authorized_keys hash-only')
    assert_case(manifest['files']['/etc/systemd/system/huge.service'].get('copy') is None,'Oversized config hash-only, recorded in skipped')
    assert_case(manifest['files']['/etc/systemd/system/new\nline.service'].get('copy') is not None,'Unusual newline filename is saved without parsing errors')
    # Mutation and detection scenarios.
    original = (r/'etc/systemd/system/splunk.service').read_bytes()
    file(r,'/etc/systemd/system/splunk.service','[Service]\nExecStart=/bin/false\n')
    file(r,'/etc/systemd/system/unexpected.timer','[Timer]\nOnBootSec=10s\n')
    file(r,'/etc/shadow','root:changed-secret:1::::::\n',0o600)
    ssh.chmod(0o600)
    inputs.unlink()
    file(r,'/etc/systemd/system/new\nline.service','[Service]\nExecStart=/bin/false\n')
    changed = command(r,'--check',expected=1)
    report = pathlib.Path(changed.stdout.split('REPORT: ')[1].splitlines()[0])
    findings=json.loads((report/'differences.json').read_text())
    statuses={x['path']: x['status'] for x in findings}
    assert_case(statuses['/etc/systemd/system/unexpected.timer']=='ADDED','New timer detected')
    assert_case(statuses['/etc/systemd/system/splunk.service']=='MODIFIED','Modified service unit detected')
    assert_case(statuses['/opt/splunk/etc/system/local/inputs.conf']=='MISSING','Deleted Splunk receiver config detected')
    assert_case(statuses['/etc/shadow']=='MODIFIED' and not next(x['restorable'] for x in findings if x['path']=='/etc/shadow'),'Changed shadow detected but not auto-restored')
    assert_case('/etc/systemd/system/new\nline.service' in statuses,'Newline filename safely compared')
    assert_case(ssh.stat().st_mode & 0o777 == 0o600,'Check does not modify live config')
    preview = command(r,'--restore','--dry-run',expected=1)
    assert_case('DRY-RUN: no writes' in preview.stdout and (r/'etc/systemd/system/splunk.service').read_bytes()!=original,'Dry-run does not restore')
    restore = command(r,'--restore','--lab-approve',expected=1)
    assert_case((r/'etc/systemd/system/splunk.service').read_bytes()==original,'Modified unit restored')
    assert_case(inputs.read_text().startswith('[splunktcp://9997]'),'Deleted input restored')
    assert_case(ssh.stat().st_mode & 0o777 == 0o644,'Original owner/mode restored')
    assert_case((r/'etc/shadow').read_text().startswith('root:changed-secret'),'Sensitive identity database left untouched')
    assert_case((r/'etc/systemd/system/unexpected.timer').exists(),'New suspicious timer remains for explicit investigation')
    assert_case('POST-RESTORE DIFFERENCES REMAINING:' in restore.stdout,'Post-restoration check emitted')
    # Ensure source objects are validated before doing anything further.
    objid=manifest['files']['/etc/systemd/system/splunk.service']['copy']
    obj=r/'.ccdc-v2-state/objects'/objid
    obj.write_text('baseline-corrupted')
    failed=command(r,'--restore','--lab-approve',expected=2)
    assert_case('copy missing/corrupt' in failed.stderr,'Corrupt baseline object causes refusal')
    # Symlink path-component protection: run a separate scenario with valid objects again.
    obj.write_bytes(original)
    file(r, '/etc/systemd/system/splunk.service', '[Service]\nExecStart=/bin/false\n')
    target = r/'escape-target'
    target.mkdir()
    (r/'opt/splunk/etc/system/local').rename(r/'opt/splunk/etc/system/old-local')
    (r/'opt/splunk/etc/system/local').symlink_to(target, target_is_directory=True)
    attempted=command(r,'--restore','--lab-approve',expected=2)
    assert_case('FAILED' in attempted.stderr and 'symlinked path component' in attempted.stderr,'Symlink-component path blocks restore')

with tempfile.TemporaryDirectory(prefix='ccdc-v2-profile-tests-') as d:
    r=pathlib.Path(d)
    file(r,'/etc/ssh/sshd_config','PermitRootLogin no\n')
    splunk=file(r,'/opt/splunk/etc/system/local/inputs.conf','[splunktcp://9997]\ndisabled=0\n')
    command(r,'--baseline','--profile','host',expected=0)
    assert_case((r/'.ccdc-v2-state-host/manifest.json').exists(),'Host profile has independent baseline')
    splunk.write_text('injected config change')
    assert_case(command(r,'--check','--profile','host',expected=0).returncode==0,'Host profile intentionally excludes Splunk app/config drift')
    file(r,'/etc/cron.d/unexpected','* * * * * root /bin/false\n')
    assert_case(command(r,'--check','--profile','host',expected=1).returncode==1,'Host profile detects new cron persistence')
    assert_case(command(r,'--baseline','--profile','deployed',expected=0).returncode==0,'Separate deployed baseline can be added later without overwriting host baseline')

# Live restore guard is tested with a synthetic SSH environment. It must refuse
# before touching /root or any real guest path.
ssh_env=os.environ.copy()
ssh_env['SSH_CONNECTION']='10.0.0.1 2222 10.0.0.2 22'
refused=subprocess.run(['bash',str(SCRIPT),'--restore'],capture_output=True,text=True,env=ssh_env)
assert_case(refused.returncode==2 and 'SSH sessions are refused' in refused.stderr,
            'Live restore refuses simulated SSH session before touching host')

print(f'ALL {passed} SANDBOX ASSERTIONS PASSED')
