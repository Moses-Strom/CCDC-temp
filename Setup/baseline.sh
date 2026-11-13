#!/usr/bin/env bash
# CCDC conservative baseline/check/selective restore prototype.
# Bash entrypoint; Python 3 standard library handles NUL/newline-safe paths and JSON.
# No service restarts, firewall changes, user changes, removal/quarantine of added files.
set -euo pipefail
umask 077
usage() {
  cat <<'USAGE'
Usage: sudo bash ccdc-baseline-v2.sh --baseline|--check|--restore [--profile host|deployed] [--dry-run] [--deep]
       LAB ONLY: --lab-root /absolute/test/root [--lab-approve]

--baseline    One-time atomic snapshot (refuses overwrite).
--profile     deployed (default: full host+Splunk inventory), host (excludes /opt/splunk).
--check       Read-only comparison; exit 0 clean, 1 differences, 2 errors.
--restore     Review and selectively recover changed/missing files copied at baseline.
--dry-run     Preview without writing to live filesystem (with --restore).
--deep        Run dpkg --verify in live --check mode (may be slow/noisy).
--lab-root    Synthetic filesystem testing only; never use for real restore.
--lab-approve Noninteractive restore for the synthetic lab root ONLY.

No remote verification, no full system backup, no assurance of trust after root compromise.
USAGE
}
mode=''; dry=0; deep=0; lab_root=''; lab_approve=0; profile='deployed'
while (($#)); do
 case "$1" in
  --baseline|--check|--restore) [[ -z "$mode" ]] || { usage >&2; exit 2; }; mode="$1";;
  --profile) [[ $# -ge 2 && ( $2 == host || $2 == deployed ) ]] || { echo 'ERROR: profile must be host or deployed' >&2; exit 2; }; profile="$2"; shift;;
  --dry-run) dry=1;;
  --deep) deep=1;;
  --lab-root) [[ $# -ge 2 ]] || exit 2; lab_root="$2"; shift;;
  --lab-approve) lab_approve=1;;
  --help|-h) usage; exit 0;;
  *) echo "Unknown argument: $1" >&2; usage >&2; exit 2;;
 esac
 shift
done
[[ -n "$mode" ]] || { usage >&2; exit 2; }
[[ $(id -u) -eq 0 ]] || { echo 'ERROR: root privileges required' >&2; exit 2; }
if ((dry)) && [[ "$mode" != --restore ]]; then echo 'ERROR: --dry-run requires --restore' >&2; exit 2; fi
if ((deep)) && [[ "$mode" != --check ]]; then echo 'ERROR: --deep requires --check' >&2; exit 2; fi
if [[ -n "$lab_root" ]]; then
 [[ "$lab_root" == /* && "$lab_root" != / && -d "$lab_root" && ! -L "$lab_root" ]] || { echo 'ERROR: invalid lab root' >&2; exit 2; }
 root="$(realpath -e -- "$lab_root")"
 [[ "$root" != / ]] || exit 2
 state="$root/.ccdc-v2-state${profile/deployed/}"
 [[ "$profile" != host ]] || state="$root/.ccdc-v2-state-host"
else
 root=/
 state=/root/ccdc-baseline-v2
 [[ "$profile" != host ]] || state=/root/ccdc-baseline-v2-host
fi
if ((lab_approve)) && [[ -z "$lab_root" || "$mode" != --restore ]]; then
 echo 'ERROR: --lab-approve permitted only with --restore --lab-root' >&2; exit 2
fi
# Recovery is intentionally restricted to the local NETLAB/VM console. A sudo
# invocation may scrub SSH_* environment variables, so also trace parent processes.
is_ssh_session() {
  [[ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-}" ]] && return 0
  local pid=$$ comm ppid hops=0
  while ((pid > 1 && hops < 40)); do
    comm="$(ps -o comm= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
    case "$comm" in sshd|sshd-session) return 0;; esac
    ppid="$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
    [[ "$ppid" =~ ^[0-9]+$ ]] || break
    pid="$ppid"
    hops=$((hops+1))
  done
  return 1
}
if [[ "$mode" == --restore && -z "$lab_root" ]] && is_ssh_session; then
  echo 'ERROR: Live restore requires NETLAB/VM console; SSH sessions are refused.' >&2
  exit 2
fi
# Explicit trusted-relative inventory roots, deliberately excludes mutable Splunk var/lib logs and indexes.
python3 - "$mode" "$root" "$state" "$dry" "$deep" "$lab_approve" "$profile" <<'PYTHON'
import fcntl, hashlib, json, os, pathlib, re, shutil, stat, subprocess, sys, tempfile, time

mode, root, state, dry_s, deep_s, lab_approve_s, profile = sys.argv[1:]
dry, deep, lab_approve = bool(int(dry_s)), bool(int(deep_s)), bool(int(lab_approve_s))
lab = root != '/'
paths = [
 '/etc/systemd/system', '/etc/systemd/system.control', '/etc/systemd/system-generators',
 '/etc/systemd/user', '/etc/systemd/user-generators',
 '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly',
 '/etc/cron.yearly', '/etc/cron.allow', '/etc/cron.deny', '/etc/crontab',
 '/etc/anacrontab', '/etc/logrotate.d', '/etc/update-motd.d',
 '/var/spool/cron/crontabs', '/var/spool/cron/atjobs', '/etc/at.allow', '/etc/at.deny',
 '/etc/init.d', '/etc/rc.local', '/etc/ssh', '/etc/sudoers', '/etc/sudoers.d',
 '/etc/pam.d', '/etc/security', '/etc/profile', '/etc/bash.bashrc', '/etc/profile.d',
 '/etc/login.defs', '/etc/environment', '/etc/environment.d', '/etc/polkit-1/rules.d',
 '/etc/udev/rules.d', '/etc/network/if-up.d', '/etc/network/if-pre-up.d',
 '/etc/NetworkManager/dispatcher.d', '/etc/network/interfaces', '/etc/network/interfaces.d',
 '/etc/netplan', '/etc/modprobe.d', '/etc/modules-load.d',
 '/etc/tmpfiles.d', '/etc/ld.so.preload', '/etc/ld.so.conf', '/etc/ld.so.conf.d',
 '/etc/apt/apt.conf.d', '/etc/apt/sources.list', '/etc/apt/sources.list.d',
 '/etc/sysctl.conf', '/etc/sysctl.d', '/etc/nftables.conf', '/etc/iptables', '/etc/ufw',
 '/etc/fail2ban', '/etc/audit',
 '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
 '/usr/local/bin', '/usr/local/sbin', '/usr/local/lib/systemd/system-generators',
 '/usr/lib/systemd/system', '/usr/lib/systemd/system-generators',
 '/usr/lib/systemd/user-generators',
 '/lib/systemd/system', '/run/systemd/system', '/run/systemd/system.control',
 '/run/systemd/system-generators',
 '/run/systemd/generator', '/run/systemd/generator.early', '/run/systemd/generator.late',
 '/opt/splunk/etc', '/opt/splunk/bin/scripts', '/root/.ssh',
 '/root/.bashrc', '/root/.profile', '/root/.bash_profile', '/root/.config/systemd/user',
]
if profile == 'host':
    paths = [path for path in paths if not path.startswith('/opt/splunk/')]
# Files from ordinary user home .ssh tracked without crawling whole home trees.
home_dir = os.path.join(root, 'home')
if os.path.isdir(home_dir):
    for n in sorted(os.listdir(home_dir)):
        if n not in ('.', '..'):
            for suffix in ('.ssh','.bashrc','.profile','.bash_profile','.config/systemd/user'):
                paths.append('/home/' + n + '/' + suffix)
MAX_COPY = 3 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024

def actual(rel): return os.path.join(root, rel.lstrip('/'))
def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()

def is_sensitive(rel):
    p = rel.lower()
    if rel in ('/etc/passwd','/etc/shadow','/etc/group','/etc/gshadow'): return True
    if rel.startswith(('/root/.ssh/','/home/')) and '/.ssh/' in p: return True
    if p.startswith('/etc/ssh/ssh_host_'): return True
    if p == '/opt/splunk/etc/passwd' or p.endswith('/splunk.secret'): return True
    if p.endswith(('.pem','.key','.p12','.pfx','.crt')): return True
    return False

def can_restore(rel):
    # High-risk identity and secret files remain audit-only. No restoration of vendor binaries.
    if is_sensitive(rel): return False
    pref = ('/etc/systemd/system/', '/etc/cron.', '/etc/init.d/',
            '/var/spool/cron/crontabs/', '/etc/ssh/sshd_config',
            '/etc/sudoers', '/etc/profile.d/', '/etc/udev/rules.d/',
            '/etc/network/if-', '/usr/local/bin/', '/usr/local/sbin/',
            '/opt/splunk/etc/system/local/', '/opt/splunk/etc/apps/',
            '/opt/splunk/bin/scripts/')
    return rel in ('/etc/crontab','/etc/rc.local','/etc/profile','/etc/bash.bashrc',
                   '/etc/ld.so.preload') or rel.startswith(pref)

def inspect(rel):
    p = actual(rel)
    s = os.lstat(p)
    if stat.S_ISREG(s.st_mode):
        typ, val = 'file', sha(p)
    elif stat.S_ISLNK(s.st_mode):
        typ, val = 'symlink', os.readlink(p)
    elif stat.S_ISDIR(s.st_mode):
        typ, val = 'dir', ''
    else:
        typ, val = 'special', ''
    return {'path':rel, 'type':typ, 'mode':stat.S_IMODE(s.st_mode),
            'uid':s.st_uid, 'gid':s.st_gid, 'size':s.st_size if typ=='file' else 0, 'value':val}

def inventory():
    found = {}
    errors = []
    for rel in paths:
        target = actual(rel)
        if not os.path.lexists(target): continue
        try:
            # Inventory the root itself; don't follow directory symlinks.
            if rel not in found: found[rel] = inspect(rel)
            if not os.path.isdir(target) or os.path.islink(target): continue
            def err(exc): errors.append(f'{rel}: {exc}')
            for base, dirs, files in os.walk(target, topdown=True, followlinks=False, onerror=err):
                for name in dirs + files:
                    p = os.path.join(base, name)
                    logical = '/' + os.path.relpath(p, root).replace(os.sep, '/')
                    if logical not in found:
                        try: found[logical] = inspect(logical)
                        except (OSError, ValueError) as exc: errors.append(f'{logical!r}: {exc}')
        except (OSError, ValueError) as exc: errors.append(f'{rel!r}: {exc}')
    if errors:
        raise RuntimeError('Incomplete inventory; refusing to call state clean. Examples: ' + '; '.join(errors[:8]))
    return found

def write_json(path, obj):
    with open(path,'w',encoding='utf8') as fh:
        json.dump(obj,fh,sort_keys=True,indent=2,ensure_ascii=True)
        fh.write('\n')
        fh.flush(); os.fsync(fh.fileno())
    os.chmod(path,0o600)

def read_json(path):
    with open(path,encoding='utf8') as fh: return json.load(fh)

def diff_inventory(before, now):
    out=[]
    for rel in sorted(set(before) | set(now)):
        old, new = before.get(rel), now.get(rel)
        if not old: what='ADDED'
        elif not new: what='MISSING'
        elif any(old[k] != new[k] for k in ('type','mode','uid','gid','size','value')): what='MODIFIED'
        else: continue
        delta=[] if not (old and new) else [k for k in ('type','mode','uid','gid','size','value') if old[k]!=new[k]]
        out.append({'path':rel,'status':what,'attributes':delta,'restorable':what != 'ADDED' and
                    bool(old and old.get('copy')) and (not new or new['type']=='file')})
    return out

def diagnostics(report):
    if lab: return
    commands = {
        'ports.txt':['ss','-H','-lntup'],
        'systemd-services.txt':['systemctl','list-units','--type=service','--all','--no-pager','--no-legend'],
        'systemd-timers.txt':['systemctl','list-timers','--all','--no-pager'],
        'systemd-unit-files.txt':['systemctl','list-unit-files','--all','--no-pager'],
        'network-addresses.txt':['ip','-br','addr'],
        'ufw.txt':['ufw','status','verbose'],
        'splunk-btool-check.txt':['/opt/splunk/bin/splunk','btool','check'],
    }
    if deep: commands['dpkg-verify.txt']=['dpkg','--verify']
    for name,argv in commands.items():
        dest=os.path.join(report,name)
        try:
            cp=subprocess.run(argv,capture_output=True,text=True,timeout=15 if name != 'dpkg-verify.txt' else 120)
            msg=f'exit_status={cp.returncode}\n'+cp.stdout[:2_000_000]+cp.stderr[:500_000]
        except (OSError,subprocess.TimeoutExpired) as exc:
            msg=f'UNAVAILABLE: {exc}\n'
        with open(dest,'w') as f: f.write(msg)
        os.chmod(dest,0o600)

def report_dir():
    base=os.path.join(state,'reports')
    os.makedirs(base,mode=0o700,exist_ok=True)
    return tempfile.mkdtemp(prefix='scan-',dir=base)

def check_safe_parent(file):
    # Refuse any symlink component (including destination) before root write.
    cur=root
    for part in file.lstrip('/').split('/'):
        if not part or part in ('.','..'): return False
        cur=os.path.join(cur,part)
        if os.path.islink(cur): return False
    return True

def make_baseline():
    if os.path.lexists(state): raise RuntimeError(f'Baseline already exists: {state}')
    parent=os.path.dirname(state)
    os.makedirs(parent,mode=0o700,exist_ok=True)
    if os.path.islink(parent): raise RuntimeError('Symlinked baseline parent refused')
    stage=tempfile.mkdtemp(prefix='.ccdc-stage-',dir=parent)
    try:
        os.chmod(stage,0o700)
        os.mkdir(os.path.join(stage,'objects'),0o700)
        now=inventory()
        copied=0; skipped=[]
        for rel,item in sorted(now.items()):
            if item['type'] != 'file' or not can_restore(rel): continue
            if item['size'] > MAX_COPY or copied + item['size'] > MAX_TOTAL:
                skipped.append({'path':rel,'reason':'size budget exceeded'}); continue
            target=os.path.join(stage,'objects',item['value'])
            if not os.path.exists(target):
                # copying from a source may race live changes; compare copied hash.
                shutil.copyfile(actual(rel),target,follow_symlinks=False)
                os.chmod(target,0o600)
                if sha(target) != item['value']:
                    raise RuntimeError(f'Source changed during snapshot: {rel!r}')
                copied += item['size']
            item['copy']=item['value']
        write_json(os.path.join(stage,'manifest.json'), {'version':2,'created_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'root':root,'profile':profile,'files':now,'skipped':skipped})
        os.rename(stage,state)
        print(f'BASELINE CREATED: {state} | inventory {len(now)} | restorable {sum(bool(x.get("copy")) for x in now.values())} | skipped {len(skipped)} | copy bytes {copied}')
        print('Do NOT create this baseline unless the guest is believed trusted. CCDC snapshots stay ON THIS GUEST; root compromise can tamper with them.')
        return 0
    except Exception:
        shutil.rmtree(stage,ignore_errors=True)
        raise

def check_or_restore():
    manifest=read_json(os.path.join(state,'manifest.json'))
    if manifest.get('version')!=2 or manifest.get('root')!=root or manifest.get('profile')!=profile: raise RuntimeError('Baseline format/root mismatch')
    before=manifest['files']
    for rel,entry in before.items():
        if entry.get('copy'):
            digest=entry['copy']
            if not re.fullmatch(r'[0-9a-f]{64}',digest): raise RuntimeError('Invalid object hash in baseline')
            obj=os.path.join(state,'objects',digest)
            if not os.path.isfile(obj) or sha(obj)!=digest:
                raise RuntimeError(f'Baseline copy missing/corrupt for {rel!r}; refusing restore/check')
    now=inventory()
    diff=diff_inventory(before,now)
    report=report_dir()
    write_json(os.path.join(report,'differences.json'),diff)
    with open(os.path.join(report,'changes.txt'),'w') as out:
        for d in diff:
            row=f"{d['status']:8} {d['path']!r} {','.join(d['attributes'])} restorable={d['restorable']}"
            print(row,file=out)
    diagnostics(report)
    added=sum(x['status']=='ADDED' for x in diff)
    missing=sum(x['status']=='MISSING' for x in diff)
    modified=sum(x['status']=='MODIFIED' for x in diff)
    print(f'DIFFERENCES: added={added}, missing={missing}, modified={modified}. REPORT: {report}')
    for d in diff[:60]: print(f"{d['status']:8} {d['path']!r} {','.join(d['attributes'])}")
    if len(diff)>60: print(f'... {len(diff)-60} more in {report}/changes.txt')
    if mode=='--check':
        print('Note: clean inventory does NOT prove clean runtime, valid scored services, or trusted root.')
        return 1 if diff else 0
    candidates=[d for d in diff if d['restorable']]
    print('Restore never removes new files, restarts services, resets accounts or changes runtime firewall rules.')
    if not candidates:
        print('No backed-up files eligible for restoration. Examine added files/identities separately.')
        return 1 if diff else 0
    for i,d in enumerate(candidates,1): print(f'  [{i}] {d["path"]!r}')
    if dry:
        print('DRY-RUN: no writes. A nonzero exit indicates differences remain.')
        return 1
    if lab_approve: chosen=candidates
    else:
        # The Bash process feeds this Python source through stdin; console input must use /dev/tty.
        try:
            with open('/dev/tty','r+') as tty:
                tty.write('Select restore numbers comma-separated, ALL, or Enter to cancel: '); tty.flush()
                choice=tty.readline().strip()
                if choice=='ALL': chosen=candidates
                else:
                    selected={int(x) for x in choice.split(',') if x.strip().isdigit()}
                    chosen=[d for i,d in enumerate(candidates,1) if i in selected]
                if not chosen:
                    print('CANCELLED'); return 1
                tty.write(f'Type RESTORE {len(chosen)} to confirm: '); tty.flush()
                if tty.readline().strip()!=f'RESTORE {len(chosen)}':
                    print('CANCELLED'); return 1
        except OSError as exc: raise RuntimeError(f'Interactive console required: {exc}')
    rollback=os.path.join(report,'pre-restore')
    os.mkdir(rollback,0o700)
    ok=0; failures=0
    for d in chosen:
        rel=d['path']; old=before[rel]; dest=actual(rel)
        try:
            if not check_safe_parent(rel): raise RuntimeError('symlinked path component')
            parent=os.path.dirname(dest)
            if not os.path.isdir(parent): raise RuntimeError('parent missing/not directory')
            if os.path.lexists(dest) and not os.path.isfile(dest): raise RuntimeError('destination no longer a regular file')
            # Recheck that source is unchanged since the preview; no silent clobber.
            if now.get(rel) != (inspect(rel) if os.path.lexists(dest) else None):
                raise RuntimeError('destination changed since preview')
            digest=old['copy']
            source=os.path.join(state,'objects',digest)
            if sha(source)!=digest: raise RuntimeError('baseline copy hash mismatch')
            if os.path.isfile(dest):
                before_path=os.path.join(rollback,f'{len(os.listdir(rollback)):06d}.before')
                shutil.copy2(dest,before_path,follow_symlinks=False)
                os.chmod(before_path,0o600)
                with open(before_path+'.path','w') as f: f.write(rel)
            fd,tmp=tempfile.mkstemp(prefix='.ccdc-restore-',dir=parent)
            try:
                with os.fdopen(fd,'wb') as output, open(source,'rb') as sf: shutil.copyfileobj(sf,output)
                os.chown(tmp,old['uid'],old['gid'])
                os.chmod(tmp,old['mode'])
                if sha(tmp)!=digest: raise RuntimeError('staged file failed hash check')
                if not check_safe_parent(rel): raise RuntimeError('symlink changed during staging')
                os.replace(tmp,dest)
            finally:
                if os.path.exists(tmp): os.unlink(tmp)
            print(f'RESTORED {rel!r}')
            ok += 1
        except Exception as exc:
            print(f'FAILED {rel!r}: {exc}',file=sys.stderr)
            failures+=1
    print(f'RESTORE SUMMARY: ok={ok} failed={failures} | rollback folder={rollback}')
    if not lab:
        print('DO NOT restart Splunk without first reviewing new persistence, running syntax checks, and checking scoring.')
        print('Suggested checks: visudo -c ; /usr/sbin/sshd -t ; /opt/splunk/bin/splunk btool check')
    after=diff_inventory(before,inventory())
    write_json(os.path.join(report,'post-restore-differences.json'),after)
    print(f'POST-RESTORE DIFFERENCES REMAINING: {len(after)} (see post-restore-differences.json)')
    return 2 if failures else (1 if after else 0)

try:
    # Serialize concurrent invocations to avoid accidental overlapping baseline/report operations.
    lock_fd=os.open(state+'.lock',os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    fcntl.flock(lock_fd,fcntl.LOCK_EX)
    if os.path.islink(state): raise RuntimeError('Symlinked state directory refused')
    if mode == '--baseline':
        status=make_baseline()
    elif not os.path.isfile(os.path.join(state,'manifest.json')):
        raise RuntimeError(f'No completed baseline manifest found: {state}')
    else:
        status=check_or_restore()
except Exception as ex:
    print(f'ERROR: {ex}',file=sys.stderr)
    status=2
sys.exit(status)
PYTHON
