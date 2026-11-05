#!/usr/bin/env bash
# CCDC Four Security Dashboards - offline/self-contained installer
# Target: Existing Splunk Enterprise (e.g. Debian 12 / Splunk 10.0.2)
# Installs 4 original Classic/Simple XML dashboards as a SEPARATE Splunk app.
# No internet required. Does not install Splunk, forwarders, or alerts.
# Does not alter receiving ports, accounts, global indexes, or existing apps.
# Does not restart Splunk.
set -Eeuo pipefail

APP_NAME="ccdc_four_dashboards"
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
APPS_DIR="$SPLUNK_HOME/etc/apps"
TARGET="$APPS_DIR/$APP_NAME"
MODE="${1:-install}"

usage() {
  cat <<'USAGE'
Usage: sudo bash setup-ccdc-four-dashboards.sh [install|--update|--verify]
  install    Install these four dashboards in a new, separate Splunk app (default)
  --update  Back up and replace only this app with the four bundled dashboards
  --verify  Verify installed dashboard files against the original bundled hashes

Environment: SPLUNK_HOME=/opt/splunk by default.
This installer requires an existing Splunk Enterprise installation.
It never restarts Splunk, enables scheduled searches, or changes log inputs.
USAGE
}

# File hashes for the exact XML files provided with this installer.
# Verification detects accidental editing/corruption, not malicious edits to
# the installer and the checksums together.
verify_dir() {
  local dir="$1" file hash actual count
  if [[ ! -d "$dir/default/data/ui/views" ]]; then
    echo "ERROR: Dashboard view directory missing in $dir" >&2; return 1
  fi
  count=$(find "$dir/default/data/ui/views" -maxdepth 1 -type f -name '*.xml' | wc -l)
  if [[ "$count" -ne 4 ]]; then
    echo "ERROR: Expected 4 dashboard XMLs, found $count" >&2; return 1
  fi
  [[ -f "$dir/default/app.conf" && -f "$dir/default/data/ui/nav/default.xml" && -f "$dir/metadata/default.meta" ]] || {
    echo "ERROR: Missing Splunk app metadata/navigation files" >&2; return 1;
  }
  while read -r file hash; do
    [[ -f "$dir/default/data/ui/views/$file" ]] || {
      echo "ERROR: Missing dashboard $file" >&2; return 1;
    }
    actual=$(sha256sum "$dir/default/data/ui/views/$file" | awk '{print $1}')
    if [[ "$actual" != "$hash" ]]; then
      echo "ERROR: Dashboard changed or corrupted: $file" >&2; return 1
    fi
  done <<'EXPECTED_SHA256'
attack_surface_overview.xml 2c562f3cc265546b926deaf27bf5336ddac43ec1d42d67c1f735e63703602f3a
windows_active_directory.xml 25387508333085dae2bde55ef5205885361944d44aee6c04b65accffa8a330e3
linux_server_services.xml 6f86bf818cbb3841e38db1368840f4aa35a74d26f33ac1e5bb8ebd72cc761adc
firewall_log_coverage.xml 0e4099adfc15b30cdf392b108b799a0ab9ef4aaa700cde924dd8a13fcd8f6a2a
EXPECTED_SHA256
  echo "PASS: Four original dashboard XML files and app metadata found in $dir"
}

if [[ $# -gt 1 ]]; then usage; exit 2; fi
case "$MODE" in
  -h|--help) usage; exit 0 ;;
  --verify)
    verify_dir "$TARGET"
    exit 0 ;;
  install|--update) ;;
  *) usage; exit 2 ;;
esac

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run with sudo on your Splunk server." >&2; exit 1
fi
if [[ ! -x "$SPLUNK_HOME/bin/splunk" || ! -d "$APPS_DIR" ]]; then
  echo "ERROR: Splunk Enterprise not found in $SPLUNK_HOME" >&2
  echo "Set SPLUNK_HOME if your installation uses a different path." >&2
  exit 1
fi
if [[ "$MODE" == 'install' && -e "$TARGET" ]]; then
  echo "ERROR: Already installed: $TARGET" >&2
  echo "To replace these four dashboards safely, use --update." >&2
  exit 1
fi
if [[ "$MODE" == '--update' && ! -d "$TARGET" ]]; then
  echo "ERROR: No existing app to update. Run install instead." >&2; exit 1
fi

WORKDIR=$(mktemp -d)
APPROOT="$WORKDIR/$APP_NAME"
mkdir -p "$APPROOT/default/data/ui/views" "$APPROOT/default/data/ui/nav" "$APPROOT/metadata"
STAGE_PATH=""
HOLD_PATH=""
cleanup() {
  rm -rf -- "$WORKDIR"
  if [[ -n "$STAGE_PATH" && -d "$STAGE_PATH" ]]; then rm -rf -- "$STAGE_PATH"; fi
  # Do not erase HOLD_PATH on failure: this is recoverable original data.
}
trap cleanup EXIT

cat > "$APPROOT/default/app.conf" <<'APP_CONF'
[install]
is_configured = 1
state = enabled

[ui]
is_visible = 1
label = CCDC Security Monitoring - Four Dashboards

[launcher]
author = CCDC Defense Team
description = Standalone offline Classic XML dashboards for CCDC monitoring.
version = 1.0.0
APP_CONF

cat > "$APPROOT/metadata/default.meta" <<'META'
[]
access = read : [ * ], write : [ admin ]
export = system

[views]
access = read : [ * ], write : [ admin ]
export = system
META

cat > "$APPROOT/default/data/ui/nav/default.xml" <<'NAV'
<nav>
  <view name="attack_surface_overview" default="true" />
  <view name="windows_active_directory" />
  <view name="linux_server_services" />
  <view name="firewall_log_coverage" />
</nav>
NAV

cat > "$APPROOT/default/data/ui/views/attack_surface_overview.xml" <<'CCDC_XML_END_ATTACK_SURFACE_OVERVIEW_XML'
<?xml version="1.0" encoding="utf-8"?>
<form version="1.1">
  <label>CCDC | Attack Surface Overview</label>
  <description>Triage view. Signals are not proof of compromise. Empty panels may indicate missing ingestion, audit policy, or incompatible field names. Change time / index to investigate.</description>
  <fieldset submitButton="false" autoRun="true">
    <input type="time" token="timer" searchWhenChanged="true">
      <label>Time window</label>
      <default>
        <earliest>-30m</earliest>
        <latest>now</latest>
      </default>
    </input>
    <input type="dropdown" token="data_index" searchWhenChanged="true">
      <label>Event index</label>
      <choice value="*">All accessible event indexes (slowest)</choice>
      <choice value="main">main</choice>
      <choice value="wineventlog">wineventlog</choice>
      <choice value="windowslogs">windowslogs</choice>
      <choice value="os">os</choice>
      <choice value="linux">linux</choice>
      <choice value="network">network</choice>
      <default>*</default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>Event sources seen (verify ingestion first)</title>
      <table>
        <search>
          <query>index=$data_index$
| stats count as events max(_time) as last_seen by host, sourcetype
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort - events
| head 30</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Windows failed logins (4625)</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode=4625 OR EventID=4625)
| eval account=coalesce(TargetUserName,Account_Name,user,"unknown"), src_ip=coalesce(IpAddress,Source_Network_Address,src_ip,src,"unknown")
| stats count as failures by host,account,src_ip
| sort - failures
| head 30</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Linux SSH successes and failures</title>
      <table>
        <search>
          <query>index=$data_index$ ("Failed password" OR "Accepted password" OR "Invalid user")
| rex field=_raw "from\s+(?&lt;src_ip&gt;(?:\d{1,3}\.){3}\d{1,3})"
| eval result=case(searchmatch("Accepted password"),"ACCEPTED",searchmatch("Failed password"),"FAILED",searchmatch("Invalid user"),"INVALID USER",true(),"OTHER")
| stats count by host,src_ip,result
| sort - count</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Potential Windows RDP logins (4624 / type 10)</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode=4624 OR EventID=4624)
| eval logon_type=coalesce(LogonType,Logon_Type), account=coalesce(TargetUserName,Account_Name,user,"unknown")
| where tostring(logon_type)="10"
| eval src_ip=coalesce(IpAddress,Source_Network_Address,src_ip,"unknown")
| stats count as logins max(_time) as last_seen by host,account,src_ip
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort - logins</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Windows account / group / service changes</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode IN (4720,4728,4732,4756,4738,7045,1102,4698) OR EventID IN (4720,4728,4732,4756,4738,7045,1102,4698))
| eval id=coalesce(EventCode,EventID)
| table _time host id Account_Name TargetUserName Message
| sort - _time</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>HTTP errors (requires access-log forwarding)</title>
      <table>
        <search>
          <query>index=$data_index$ ("HTTP/1.0" OR "HTTP/1.1" OR "HTTP/2" OR sourcetype=access_* OR sourcetype=nginx*)
| rex field=_raw "\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^\"]+\s+HTTP/[^\"]+\"\s+(?&lt;raw_http_code&gt;\d{3})"
| eval http_code=coalesce(status,status_code,raw_http_code)
| where isnotnull(http_code) AND tonumber(http_code)&gt;=400
| stats count as requests by host,http_code
| sort - requests</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
</form>
CCDC_XML_END_ATTACK_SURFACE_OVERVIEW_XML

cat > "$APPROOT/default/data/ui/views/windows_active_directory.xml" <<'CCDC_XML_END_WINDOWS_ACTIVE_DIRECTORY_XML'
<?xml version="1.0" encoding="utf-8"?>
<form version="1.1">
  <label>CCDC | Windows, AD, RDP, WinRM and SMB</label>
  <description>Windows logons, credential access signals, administrative changes, RDP and SMB. Some panels require additional Windows auditing, Sysmon, or Operational logs.</description>
  <fieldset submitButton="false" autoRun="true">
    <input type="time" token="timer" searchWhenChanged="true">
      <label>Time window</label>
      <default>
        <earliest>-30m</earliest>
        <latest>now</latest>
      </default>
    </input>
    <input type="dropdown" token="data_index" searchWhenChanged="true">
      <label>Event index</label>
      <choice value="*">All accessible event indexes (slowest)</choice>
      <choice value="main">main</choice>
      <choice value="wineventlog">wineventlog</choice>
      <choice value="windowslogs">windowslogs</choice>
      <choice value="os">os</choice>
      <choice value="linux">linux</choice>
      <choice value="network">network</choice>
      <default>*</default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>Windows failed authentication</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode=4625 OR EventID=4625)
| eval account=coalesce(TargetUserName,Account_Name,user,"unknown"), src_ip=coalesce(IpAddress,Source_Network_Address,src_ip,"unknown"),type=coalesce(LogonType,Logon_Type,"unknown")
| stats count as attempts min(_time) as first_seen max(_time) as last_seen by host,account,src_ip,type
| where attempts&gt;=2
| eval first_seen=strftime(first_seen,"%H:%M:%S"),last_seen=strftime(last_seen,"%H:%M:%S")
| sort - attempts</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Successful Windows authentication</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode=4624 OR EventID=4624)
| eval account=coalesce(TargetUserName,Account_Name,user,"unknown"),src_ip=coalesce(IpAddress,Source_Network_Address,src_ip,"unknown"),type=coalesce(LogonType,Logon_Type,"unknown")
| where NOT match(account,"^DWM-|^UMFD-")
| stats count as successes max(_time) as last_seen by host,account,src_ip,type
| eval last_seen=strftime(last_seen,"%H:%M:%S")
| sort - last_seen</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>RDP logins (Logon Type 10)</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode=4624 OR EventID=4624)
| eval logon_type=coalesce(LogonType,Logon_Type)
| where tostring(logon_type)="10"
| eval account=coalesce(TargetUserName,Account_Name,user),src_ip=coalesce(IpAddress,Source_Network_Address,src_ip)
| table _time host account src_ip logon_type
| sort - _time</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>WinRM activity (only if WinRM logs / process events are collected)</title>
      <table>
        <search>
          <query>index=$data_index$ (source="*WinRM*" OR sourcetype="*WinRM*" OR "wsmprovhost.exe" OR "winrs.exe")
| table _time host source EventCode user _raw
| sort - _time
| head 30</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>SMB shares accessed (5140 / 5145; needs Object Access audit)</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode IN (5140,5145) OR EventID IN (5140,5145))
| eval id=coalesce(EventCode,EventID),account=coalesce(SubjectUserName,Account_Name,user),share=coalesce(ShareName,ObjectName,RelativeTargetName),src_ip=coalesce(IpAddress,SourceAddress,Source_Network_Address)
| stats count as events by host,id,account,share,src_ip
| sort - events</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Domain / local privilege and account changes</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode IN (4720,4726,4728,4732,4756,4738,4672) OR EventID IN (4720,4726,4728,4732,4756,4738,4672))
| eval id=coalesce(EventCode,EventID),actor=coalesce(SubjectUserName,Account_Name,user),target=coalesce(TargetUserName,MemberName)
| table _time host id actor target Message
| sort - _time</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Services and scheduled tasks (7045,4697,4698)</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode IN (7045,4697,4698) OR EventID IN (7045,4697,4698))
| eval id=coalesce(EventCode,EventID)
| table _time host id ServiceName TaskName Message
| sort - _time</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>PowerShell / process execution visibility (4104,4688,Sysmon 1)</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode IN (4104,4688) OR EventID IN (4104,4688) OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1))
| eval id=coalesce(EventCode,EventID),process=coalesce(NewProcessName,Image,ProcessName)
| table _time host id user process CommandLine ScriptBlockText
| sort - _time
| head 40</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Kerberos / NTLM authentication on AD</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode IN (4768,4769,4771,4776) OR EventID IN (4768,4769,4771,4776))
| eval id=coalesce(EventCode,EventID),account=coalesce(TargetUserName,Account_Name,user,"unknown"),src_ip=coalesce(IpAddress,ClientAddress,Workstation,src_ip,"unknown"),status=coalesce(Status,FailureCode,"unknown")
| stats count as events by host,id,account,src_ip,status
| sort - events</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Windows Defender detections / config changes</title>
      <table>
        <search>
          <query>index=$data_index$ (source="*Windows Defender*" OR sourcetype="*Windows Defender*") (EventCode IN (1116,1117,5007) OR EventID IN (1116,1117,5007))
| eval id=coalesce(EventCode,EventID)
| table _time host id Message
| sort - _time</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Security logs cleared (1102) or auditing changed (4719)</title>
      <table>
        <search>
          <query>index=$data_index$ (EventCode IN (1102,4719) OR EventID IN (1102,4719))
| eval id=coalesce(EventCode,EventID)
| table _time host id Account_Name SubjectUserName Message
| sort - _time</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
</form>
CCDC_XML_END_WINDOWS_ACTIVE_DIRECTORY_XML

cat > "$APPROOT/default/data/ui/views/linux_server_services.xml" <<'CCDC_XML_END_LINUX_SERVER_SERVICES_XML'
<?xml version="1.0" encoding="utf-8"?>
<form version="1.1">
  <label>CCDC | Linux, Web, Email, FTP, SQL and Splunk</label>
  <description>Server-facing services and logins. Web/mail/FTP/SQL/DNS logs need separate inputs beyond a standard auth.log forwarder. Splunk audit panels always use _audit.</description>
  <fieldset submitButton="false" autoRun="true">
    <input type="time" token="timer" searchWhenChanged="true">
      <label>Time window</label>
      <default>
        <earliest>-30m</earliest>
        <latest>now</latest>
      </default>
    </input>
    <input type="dropdown" token="data_index" searchWhenChanged="true">
      <label>Event index</label>
      <choice value="*">All accessible event indexes (slowest)</choice>
      <choice value="main">main</choice>
      <choice value="wineventlog">wineventlog</choice>
      <choice value="windowslogs">windowslogs</choice>
      <choice value="os">os</choice>
      <choice value="linux">linux</choice>
      <choice value="network">network</choice>
      <default>*</default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>SSH failed / accepted logins</title>
      <table>
        <search>
          <query>index=$data_index$ ("Failed password" OR "Accepted password" OR "Invalid user")
| rex field=_raw "from\s+(?&lt;src_ip&gt;(?:\d{1,3}\.){3}\d{1,3})"
| rex field=_raw "for\s+(?:invalid user\s+)?(?&lt;account&gt;[^\s]+)\s+from"
| eval result=case(searchmatch("Accepted password"),"SUCCESS",searchmatch("Failed password"),"FAILED",searchmatch("Invalid user"),"INVALID USER",true(),"OTHER")
| eval src_ip=coalesce(src_ip,"unknown"),account=coalesce(account,"unknown")
| stats count as events by host,src_ip,account,result
| sort - events</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Privileged Linux actions (sudo / su)</title>
      <table>
        <search>
          <query>index=$data_index$ ("sudo:" OR "COMMAND=" OR "session opened for user root" OR "su:")
| table _time host source _raw
| sort - _time
| head 40</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Web errors by HTTP status code</title>
      <table>
        <search>
          <query>index=$data_index$ ("HTTP/1.0" OR "HTTP/1.1" OR "HTTP/2" OR sourcetype=access_* OR sourcetype=nginx*)
| rex field=_raw "\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^\"]+\s+HTTP/[^\"]+\"\s+(?&lt;raw_http_code&gt;\d{3})"
| eval http_code=coalesce(status,status_code,raw_http_code)
| where isnotnull(http_code)
| stats count as requests by host,http_code
| sort - requests</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Interesting web paths (investigate; not necessarily attacks)</title>
      <table>
        <search>
          <query>index=$data_index$ ("HTTP/1.0" OR "HTTP/1.1" OR "HTTP/2" OR sourcetype=access_* OR sourcetype=nginx*)
| rex field=_raw "\"(?&lt;method&gt;GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?&lt;uri&gt;\S+)\s+HTTP/[^\"]+\""
| where isnotnull(uri) AND match(uri,"(?i)(\.\.\/|%2e%2e|/\.env|/\.git|/wp-admin|/admin|/cgi-bin)")
| table _time host method uri clientip client_ip src _raw
| sort - _time
| head 40</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>FTP login activity (requires FTP logs)</title>
      <table>
        <search>
          <query>index=$data_index$ ("vsftpd" OR "proftpd" OR "FAIL LOGIN" OR "OK LOGIN" OR "FTP LOGIN")
| table _time host source _raw
| sort - _time
| head 40</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Email authentication: SMTP / IMAP / POP3</title>
      <table>
        <search>
          <query>index=$data_index$ ("SASL authentication failed" OR "sasl_username=" OR "imap-login:" OR "pop3-login:" OR "auth failed" OR "authentication failed")
| table _time host source _raw
| sort - _time
| head 40</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>MSSQL failed authentication (needs SQL error / audit log)</title>
      <table>
        <search>
          <query>index=$data_index$ ("Login failed for user" OR "Error: 18456" OR "18456")
| table _time host source _raw
| sort - _time
| head 40</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>DNS activity / errors (requires DNS logging)</title>
      <table>
        <search>
          <query>index=$data_index$ (sourcetype="*dns*" OR source="*named*" OR "NXDOMAIN" OR "query:")
| stats count as events by host,sourcetype,source
| sort - events
| head 30</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Splunk Web / API login attempts (built-in audit logs)</title>
      <table>
        <search>
          <query>index=_audit action="login attempt"
| eval src_ip=coalesce(clientip,src,src_ip,"unknown"),account=coalesce(user,username,"unknown")
| table _time host account src_ip info action
| sort - _time
| head 40</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Splunk audit changes (built-in audit index)</title>
      <table>
        <search>
          <query>index=_audit NOT action="login attempt"
| search action=edit OR action=update OR action=create OR action=delete
| table _time host user action info object
| sort - _time
| head 40</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
</form>
CCDC_XML_END_LINUX_SERVER_SERVICES_XML

cat > "$APPROOT/default/data/ui/views/firewall_log_coverage.xml" <<'CCDC_XML_END_FIREWALL_LOG_COVERAGE_XML'
<?xml version="1.0" encoding="utf-8"?>
<form version="1.1">
  <label>CCDC | Firewall, Network and Log Coverage</label>
  <description>Firewall panels require Palo Alto syslog collection AND field extraction. Empty results are an unknown, not proof of safety. Compare seen hosts against the full competition inventory.</description>
  <fieldset submitButton="false" autoRun="true">
    <input type="time" token="timer" searchWhenChanged="true">
      <label>Time window</label>
      <default>
        <earliest>-30m</earliest>
        <latest>now</latest>
      </default>
    </input>
    <input type="dropdown" token="data_index" searchWhenChanged="true">
      <label>Event index</label>
      <choice value="*">All accessible event indexes (slowest)</choice>
      <choice value="main">main</choice>
      <choice value="wineventlog">wineventlog</choice>
      <choice value="windowslogs">windowslogs</choice>
      <choice value="os">os</choice>
      <choice value="linux">linux</choice>
      <choice value="network">network</choice>
      <default>*</default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>Palo Alto: denied traffic (requires parsed firewall syslog)</title>
      <table>
        <search>
          <query>index=$data_index$ (sourcetype=pan:* OR sourcetype=pan_log OR source="*paloalto*")
| eval src_ip=coalesce(src,src_ip,srcip),dst_ip=coalesce(dest,dst,dest_ip),dst_port=coalesce(dport,dest_port),decision=coalesce(action,Action)
| where decision="deny" OR decision="drop" OR decision="reset-both" OR decision="reset-client" OR decision="reset-server"
| eval src_ip=coalesce(src_ip,"unknown"),dst_ip=coalesce(dst_ip,"unknown"),dst_port=coalesce(dst_port,"unknown")
| stats count as events by src_ip,dst_ip,dst_port,decision
| sort - events</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Palo Alto: many distinct destination ports (triage)</title>
      <table>
        <search>
          <query>index=$data_index$ (sourcetype=pan:* OR sourcetype=pan_log OR source="*paloalto*")
| eval src_ip=coalesce(src,src_ip,srcip),dst_port=coalesce(dport,dest_port)
| where isnotnull(src_ip) AND isnotnull(dst_port)
| stats dc(dst_port) as unique_ports count as events by src_ip
| where unique_ports&gt;=8
| sort - unique_ports</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Firewall / router syslog coverage</title>
      <table>
        <search>
          <query>index=$data_index$ (source="*syslog*" OR sourcetype=syslog OR sourcetype=pan:* OR sourcetype=pan_log OR source="*vyos*" OR source="*paloalto*")
| stats count as events max(_time) as last_seen by host,source,sourcetype
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort - events</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Event volume by host</title>
      <table>
        <search>
          <query>index=$data_index$
| stats count as events max(_time) as last_seen by host
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort - events</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Event coverage by sourcetype</title>
      <table>
        <search>
          <query>index=$data_index$
| stats count as events dc(host) as hosts by sourcetype
| sort - events</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
    <panel>
      <title>Indexed Windows events by event ID</title>
      <table>
        <search>
          <query>index=$data_index$ (sourcetype="WinEventLog:*" OR sourcetype="XmlWinEventLog:*")
| eval event_id=coalesce(EventCode,EventID)
| where isnotnull(event_id)
| stats count as events by event_id
| sort - events
| head 30</query>
          <earliest>$timer.earliest$</earliest>
          <latest>$timer.latest$</latest>
        </search>
        <option name="count">12</option>
        <option name="wrap">false</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>
</form>
CCDC_XML_END_FIREWALL_LOG_COVERAGE_XML

# Stage the verified app before modifying the installation.
verify_dir "$APPROOT"
STAGE_PATH="$APPS_DIR/.${APP_NAME}.stage.$$"
if [[ -e "$STAGE_PATH" ]]; then echo "ERROR: Staging path already exists" >&2; exit 1; fi
cp -a -- "$APPROOT" "$STAGE_PATH"
verify_dir "$STAGE_PATH"

if [[ "$MODE" == '--update' ]]; then
  BACKUP_ROOT="$SPLUNK_HOME/var/ccdc_four_dashboards_backups"
  mkdir -p "$BACKUP_ROOT"
  BACKUP="$BACKUP_ROOT/${APP_NAME}.$(date +%Y%m%d-%H%M%S).$$"
  cp -a -- "$TARGET" "$BACKUP"
  echo "Existing CCDC four-dashboard app backed up to: $BACKUP"

  HOLD_PATH="$APPS_DIR/.${APP_NAME}.previous.$$"
  if [[ -e "$HOLD_PATH" ]]; then echo "ERROR: Previous-app path exists" >&2; exit 1; fi
  mv -- "$TARGET" "$HOLD_PATH"
  if ! mv -- "$STAGE_PATH" "$TARGET"; then
    echo "ERROR: New app install failed; restoring previous app." >&2
    mv -- "$HOLD_PATH" "$TARGET"
    HOLD_PATH=""
    exit 1
  fi
  STAGE_PATH=""
  rm -rf -- "$HOLD_PATH"
  HOLD_PATH=""
else
  mv -- "$STAGE_PATH" "$TARGET"
  STAGE_PATH=""
fi

# Match the running splunkd service account, if detectable.
SPLUNK_USER=$(ps -eo user=,comm= | awk '$2 == "splunkd" { print $1; exit }' || true)
if [[ -z "$SPLUNK_USER" && -d "$SPLUNK_HOME/var/log/splunk" ]]; then
  SPLUNK_USER=$(stat -c '%U' "$SPLUNK_HOME/var/log/splunk")
fi
if [[ -n "$SPLUNK_USER" && "$SPLUNK_USER" != "UNKNOWN" ]] && id "$SPLUNK_USER" >/dev/null 2>&1; then
  SPLUNK_GROUP=$(id -gn "$SPLUNK_USER")
  chown -R "$SPLUNK_USER:$SPLUNK_GROUP" "$TARGET"
  echo "App file owner: $SPLUNK_USER:$SPLUNK_GROUP"
else
  echo "No Splunk service user detected. Ensure the Splunk service can read the app files."
fi

verify_dir "$TARGET"
cat <<'COMPLETE'

SUCCESS: Installed four CCDC dashboards in a separate Splunk app.
  App path: etc/apps/ccdc_four_dashboards (within SPLUNK_HOME)
  App name in Splunk Web: CCDC Security Monitoring - Four Dashboards
  Dashboards:
    Attack Surface Overview
    Windows & Active Directory
    Linux & Server Services
    Firewall, Network & Log Coverage

Next steps:
  1. When safe for scoring, restart Splunk using the server's normal method.
  2. In Splunk Web, open Apps > CCDC Security Monitoring - Four Dashboards.
  3. Verify logs are arriving and choose the correct index and time range.
  4. Empty panels can mean missing data, not necessarily no attacks.

This script does not install forwarders, change 9997, enable scheduled
alerts, or restart Splunk. Existing CCDC monitoring apps are left intact.
COMPLETE
