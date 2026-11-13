#!/usr/bin/env bash
# CCDC: Splunk Enterprise 10.0.x PostgreSQL-sidecar workaround for CVE-2026-20253.
# Default is READ ONLY. Run --apply only when the dependent sidecar features
# (Edge Processor, OpAmp, SPL2 data pipelines) are NOT required.
# Does not restart Splunk or change any network ports.
set -euo pipefail
umask 077
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
CONF="$SPLUNK_HOME/etc/system/local/server.conf"
MODE="${1:---check}"
case "$MODE" in
  --check|--apply) ;;
  *) printf '%s\n' 'Usage: sudo bash ccdc-mitigate-postgres.sh [--check|--apply]' >&2; exit 2;;
esac
say() { printf '%s\n' "$*"; }
show_status() {
  say "Configuration: $CONF"
  if [[ -f "$CONF" ]]; then
    python3 - "$CONF" <<'PY'
import configparser,sys
p=sys.argv[1]
cfg=configparser.RawConfigParser(strict=False)
try:
    with open(p,encoding='utf-8') as f:cfg.read_file(f)
    print('Local [postgres] disabled:',cfg.get('postgres','disabled',fallback='UNSET'))
except Exception as ex:
    print('REVIEW | Unable to parse local configuration:',type(ex).__name__)
PY
  else
    say 'Local [postgres] disabled: UNSET (file does not exist)'
  fi
  say 'REVIEW | No Splunk binaries executed. Verify effective config only after inspecting binary integrity.'
  say 'REVIEW | Loaded sidecar runtime state requires a separately planned Splunk restart and validation.'

}
say 'CCDC Splunk PostgreSQL sidecar security check'
say 'CVE-2026-20253 affects Splunk 10.0.0–10.0.6 (published June 2026).'
say 'Vendor workaround: [postgres] disabled = true in server.conf, restart required.'
say 'Disabling this sidecar breaks Edge Processor, OpAmp, or SPL2 data pipelines if used.'
show_status
[[ "$MODE" == --apply ]] || exit 0
[[ "${EUID:-$(id -u)}" -eq 0 ]] || { say 'FAIL | --apply requires root at the VM console' >&2;exit 1; }
if [[ -L "$CONF" ]]; then say 'FAIL | Refusing to replace a symlinked server.conf' >&2; exit 1; fi
if [[ -d "$CONF" ]]; then say 'FAIL | server.conf is a directory' >&2; exit 1; fi
say ''
say 'Before applying: confirm that this is the intended Splunk server and that the three sidecar-dependent features are not in use.'
read -r -p 'Type DISABLE-POSTGRES to opt in [anything else cancels]: ' confirm || true
[[ "$confirm" == 'DISABLE-POSTGRES' ]] || { say 'SKIP | No changes applied';exit 0; }
# The atomic editor refuses duplicate [postgres] stanzas and duplicate disabled keys,
# and preserves file ownership/mode. It avoids rewriting any unrelated stanza value.
python3 - "$CONF" <<'PY'
from pathlib import Path
import os, re, shutil, stat, sys, tempfile, time
p=Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True)
old=p.read_text(encoding='utf-8') if p.exists() else ''
lines=old.splitlines(keepends=True)
starts=[i for i,line in enumerate(lines) if re.fullmatch(r'\s*\[postgres\]\s*',line.strip(),flags=re.I)]
if len(starts)>1:
    sys.exit('FAIL | Duplicate [postgres] sections: review manually')
if starts:
    start=starts[0]; end=next((j for j in range(start+1,len(lines)) if re.match(r'^\s*\[',lines[j])),len(lines))
    matches=[j for j in range(start+1,end) if re.match(r'^\s*disabled\s*=',lines[j],re.I)]
    if len(matches)>1:
        sys.exit('FAIL | Duplicate postgres disabled keys: review manually')
    if matches:
        lines[matches[0]]='disabled = true\n'
    else:
        lines.insert(start+1,'disabled = true\n')
else:
    if lines and not lines[-1].endswith('\n'): lines[-1]+='\n'
    if lines and lines[-1].strip(): lines.append('\n')
    lines+=['[postgres]\n','disabled = true\n']
new=''.join(lines)
if new==old:
    print('SKIP | [postgres] disabled = true already set locally; file unchanged')
    sys.exit(0)
if p.exists():
    backup=p.with_name(p.name+'.ccdc-pre-postgres-'+time.strftime('%Y%m%d-%H%M%S')+'-'+str(os.getpid()))
    shutil.copy2(p,backup)
    print('Backed up config to:',backup)
else:
    backup=None
fd,name=tempfile.mkstemp(prefix='.server-conf-ccdc-',dir=str(p.parent))
try:
    with os.fdopen(fd,'w',encoding='utf-8') as f:
        f.write(new)
        f.flush();os.fsync(f.fileno())
    if p.exists():
        st=p.stat()
        os.chmod(name,stat.S_IMODE(st.st_mode))
        os.chown(name,st.st_uid,st.st_gid)
    else:
        os.chmod(name,0o644)
    os.replace(name,p)
except Exception:
    if os.path.exists(name):os.unlink(name)
    raise
print('PASS | Local workaround written; restart Splunk once, at the planned early restart')
PY
say ''
show_status
say 'REVIEW | Splunk restart is still REQUIRED to activate the change; NOT done by this helper.'
say 'REVIEW | This mitigates only applicable sidecar CVEs; it does not patch other Splunk 10.0.2 vulnerabilities.'
