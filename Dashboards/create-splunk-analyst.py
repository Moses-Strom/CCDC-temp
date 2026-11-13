#!/usr/bin/env python3
"""Create a least-privilege CCDC Splunk Web analyst (Splunk Enterprise 10.x).

Runs locally on the Splunk server; uses only Python's standard library.
Does not modify existing Splunk admin, existing users, or existing roles.
"""

import base64
import getpass
import json
import re
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen

API = "https://127.0.0.1:8089"
ROLE = "ccdc_analyst"
CAPABILITIES = (
    "search",               # search events and execute permitted saved reports
    "get_metadata",         # field and metadata discovery
    "get_typeahead",        # search assistance
    "rest_apps_view",       # view installed apps
    "rest_properties_get",  # read Splunk REST configuration endpoints
    "change_own_password",  # change own password only
)
# This bypasses self-signed certificate validation ONLY to localhost.
LOCAL_SSL = ssl._create_unverified_context()


def request(method, path, login, password, fields=None):
    url = API + path + ("&" if "?" in path else "?") + "output_mode=json"
    auth = base64.b64encode(f"{login}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    data = None
    if fields is not None:
        data = urlencode(fields).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, context=LOCAL_SSL, timeout=20) as response:
            contents = response.read().decode("utf-8", "replace")
            return json.loads(contents) if contents.strip() else {}
    except HTTPError as e:
        if e.code == 404:
            return None
        # Do not print request bodies or credentials.
        raise RuntimeError(f"Splunk API rejected {method} {path}: HTTP {e.code}") from None
    except (URLError, TimeoutError) as e:
        raise RuntimeError(f"Cannot connect to local Splunk management API on port 8089: {e.reason if isinstance(e, URLError) else e}") from None


def content(result):
    entries = (result or {}).get("entry", [])
    return entries[0].get("content", {}) if entries else {}


def main():
    print("Splunk CCDC Analyst Account Setup (local server only)")
    print("Creates one NEW Splunk Web user and a limited ccdc_analyst role.")
    print("No existing administrator account or password will be changed.\n")
    username = input("New analyst username [analyst]: ").strip() or "analyst"
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,31}", username):
        raise RuntimeError("Username must start with a letter and use only letters, digits, _, ., or - (32 chars max).")
    if username.lower() in {"admin", "splunk-system-user"}:
        raise RuntimeError("Refusing to modify a reserved account.")

    indices_raw = input("Allowed indexes [main,_internal,_audit]: ").strip() or "main,_internal,_audit"
    indexes = list(dict.fromkeys(v.strip() for v in indices_raw.split(",")))
    if not indexes or any(not re.fullmatch(r"[A-Za-z0-9_-]+", idx) for idx in indexes):
        raise RuntimeError("List explicit index names separated by commas; wildcard permissions are not allowed.")
    default_index = "main" if "main" in indexes else indexes[0]
    print(f"\nAccount: {username}\nRole: {ROLE}\nAllowed indexes: {', '.join(indexes)}")
    print("Capability set: " + ", ".join(CAPABILITIES))
    if input("Create this account? [y/N]: ").strip().lower() != "y":
        print("No changes made.")
        return

    login = input("Existing Splunk administrator username [admin]: ").strip() or "admin"
    admin_password = getpass.getpass("Existing Splunk administrator password: ")
    if not admin_password:
        raise RuntimeError("Administrator password is required.")
    analyst_password = getpass.getpass(f"New password for {username}: ")
    check = getpass.getpass("Confirm new analyst password: ")
    if not analyst_password or analyst_password != check:
        raise RuntimeError("Analyst passwords are empty or do not match.")
    del check

    # Verify admin credentials before creating anything.
    me = request("GET", "/services/authentication/current-context", login, admin_password)
    if not me:
        raise RuntimeError("Cannot verify Splunk admin authentication.")

    userpath = "/services/authentication/users/" + quote(username, safe="")
    rolepath = "/services/authorization/roles/" + quote(ROLE, safe="")
    if request("GET", userpath, login, admin_password) is not None:
        raise RuntimeError("User already exists: refusing to modify its role or password.")
    if request("GET", rolepath, login, admin_password) is not None:
        raise RuntimeError("Role already exists: refusing to overwrite a potentially different role.")

    role_fields = [("name", ROLE)]
    role_fields += [("capabilities", cap) for cap in CAPABILITIES]
    role_fields += [("srchIndexesAllowed", idx) for idx in indexes]
    role_fields += [("srchIndexesDefault", default_index)]
    role_fields += [("srchJobsQuota", "3"), ("rtSrchJobsQuota", "0"), ("srchDiskQuota", "100")]
    print("\nCreating limited role...")
    request("POST", "/services/authorization/roles", login, admin_password, role_fields)

    # Check effective role grants before assigning it to a new user.
    role_data = content(request("GET", rolepath, login, admin_password))
    actual_caps = set(role_data.get("capabilities", [])) | set(role_data.get("imported_capabilities", []))
    imports = role_data.get("imported_roles", [])
    allowed = set(CAPABILITIES)
    actual_idxs = set(role_data.get("srchIndexesAllowed", [])) | set(role_data.get("imported_srchIndexesAllowed", []))
    if imports or (actual_caps - allowed) or (actual_idxs - set(indexes)):
        raise RuntimeError(
            "New role has unexpected inherited roles/capabilities/index access. "
            "Stopped BEFORE creating a user. Inspect the role in Settings > Access controls > Roles. "
            f"Unexpected roles: {imports}; extra capabilities: {sorted(actual_caps - allowed)}; "
            f"extra indexes: {sorted(actual_idxs - set(indexes))}"
        )
    if "search" not in actual_caps:
        raise RuntimeError("Role verification failed: missing search capability. No user created.")

    print("Creating user...")
    user_fields = [
        ("name", username), ("password", analyst_password),
        ("roles", ROLE), ("realname", "CCDC Monitoring Analyst"),
    ]
    request("POST", "/services/authentication/users", login, admin_password, user_fields)
    analyst_data = content(request("GET", userpath, login, admin_password))
    roles = analyst_data.get("roles", [])
    if set(roles) != {ROLE}:
        raise RuntimeError(f"User was created, but unexpected roles assigned: {roles}. Review immediately.")

    print(f"\nSUCCESS: Splunk Web account '{username}' created with role '{ROLE}'.")
    print("Sign out from Splunk Web (port 8000) and log in as this new user.")
    print("Dashboards / saved searches must be shared with read access for this role.")
    print("No Splunk restart is normally required for REST-created users/roles.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyboardInterrupt) as exc:
        print(f"\nSTOP: {exc}", file=sys.stderr)
        sys.exit(1)
