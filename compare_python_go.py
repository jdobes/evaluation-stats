#!/usr/bin/env python3

import math
import os
import sqlite3
import sys
import requests
import json
import re
import time
import pandas as pd

VMAAS_PY_URL = "http://localhost:8080/api/vmaas/v3/vulnerabilities"
VMAAS_GO_URL = "http://localhost:8000/api/vmaas/v3/vulnerabilities"

NEVRA_RE = re.compile(
    r'((?P<e1>[0-9]+):)?(?P<pn>[^:]+)(?(e1)-|-((?P<e2>[0-9]+):)?)(?P<ver>[^-:]+)-(?P<rel>[^-:]+)\.(?P<arch>[a-z0-9_]+)')



class RPMParseException(Exception):
    """
    SRPM name parsing exception.
    """


def parse_rpm_name(rpm_name, default_epoch=None, raise_exception=False):
    """
    Extract components from rpm name.
    """
    filename = rpm_name
    if rpm_name[-4:] == '.rpm':
        filename = rpm_name[:-4]

    match = NEVRA_RE.match(filename)
    if not match:
        if raise_exception:
            raise RPMParseException("Failed to parse rpm name '%s'!" % rpm_name)
        return ('', default_epoch, '', '', '')

    name = match.group('pn')
    epoch = match.group('e1')
    if not epoch:
        epoch = match.group('e2')
    if not epoch:
        epoch = default_epoch
    version = match.group('ver')
    release = match.group('rel')
    arch = match.group('arch')
    return name, epoch, version, release, arch


class SqliteConnection:
    def __init__(self, db_file_name: str):
        self.db_file_name = db_file_name
        self.con = None

    def __enter__(self) -> sqlite3.Connection:
        self.con = sqlite3.connect(self.db_file_name)
        self.con.execute("PRAGMA foreign_keys = ON")  # Enforce foreign keys
        return self.con

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.con is not None:
            self.con.close()
            self.con = None


class SqliteCursor:
    def __init__(self, sqlite_connection: SqliteConnection):
        self.con = sqlite_connection
        self.cur = None

    def __enter__(self) -> sqlite3.Cursor:
        self.cur = sqlite3.Cursor(self.con)
        return self.cur

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.cur is not None:
            self.cur.close()
            self.cur = None


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <sqlite_file> <limit>", file=sys.stderr)
        sys.exit(1)
    sqlite_file = sys.argv[1]
    system_limit = sys.argv[2]

    durations_py = []
    durations_go = []

    with SqliteConnection(sqlite_file) as con:
        with SqliteCursor(con) as cur:
            try:
                cur.execute(f"SELECT inventory_id, vmaas_json FROM system WHERE vmaas_json != '' ORDER by inventory_id LIMIT {system_limit}")
                system = cur.fetchone()
                while system:
                    inventory_id, vmaas_json = system
                    vmaas_json = json.loads(vmaas_json)
                    vmaas_json["extended"] = True

                    start_ts = time.time()
                    resp_py = requests.post(VMAAS_PY_URL, json=vmaas_json)
                    py_done_ts = time.time()
                    resp_go = requests.post(VMAAS_GO_URL, json=vmaas_json)
                    go_done_ts = time.time()

                    py_duration = py_done_ts - start_ts
                    go_duration = go_done_ts - py_done_ts
                    durations_py.append(py_duration)
                    durations_go.append(go_duration)

                    if resp_py.status_code != resp_go.status_code:
                        print(f"system {inventory_id} returned HTTP {resp_py.status_code} from vmaas-py")
                        print(f"system {inventory_id} returned HTTP {resp_go.status_code} from vmaas-go")
                    
                    if resp_py.status_code == 200 and resp_go.status_code == 200:
                        vulns_py = resp_py.json()
                        vulns_go = resp_go.json()

                        fixed_cves_py = {cve["cve"] for cve in vulns_py["cve_list"]}
                        fixed_cves_go = {cve["cve"] for cve in vulns_go["cve_list"]}
                        fixed_cves_py_not_in_go = {cve for cve in fixed_cves_py if cve not in fixed_cves_go}
                        fixed_cves_go_not_in_py = {cve for cve in fixed_cves_go if cve not in fixed_cves_py}
                        if len(vulns_py["cve_list"]) != len(vulns_go["cve_list"]):
                            print(f"system {inventory_id} has cve_list len {len(vulns_py['cve_list'])} from vmaas-py")
                            print(f"system {inventory_id} has cve_list len {len(vulns_go['cve_list'])} from vmaas-go")
                        if fixed_cves_py_not_in_go:
                            print(f"system {inventory_id} has cve_list from vmaas-py which is not in vmaas-go: {fixed_cves_py_not_in_go}")
                        if fixed_cves_go_not_in_py:
                            print(f"system {inventory_id} has cve_list from vmaas-go which is not in vmaas-py: {fixed_cves_go_not_in_py}")
                        
                        manual_cves_py = {cve["cve"] for cve in vulns_py["manually_fixable_cve_list"]}
                        manual_cves_go = {cve["cve"] for cve in vulns_go["manually_fixable_cve_list"]}
                        manual_cves_py_not_in_go = {cve for cve in manual_cves_py if cve not in manual_cves_go}
                        manual_cves_go_not_in_py = {cve for cve in manual_cves_go if cve not in manual_cves_py}
                        if len(vulns_py["manually_fixable_cve_list"]) != len(vulns_go["manually_fixable_cve_list"]):
                            print(f"system {inventory_id} has manually_fixable_cve_list len {len(vulns_py['manually_fixable_cve_list'])} from vmaas-py")
                            print(f"system {inventory_id} has manually_fixable_cve_list len {len(vulns_go['manually_fixable_cve_list'])} from vmaas-go")
                        if manual_cves_py_not_in_go:
                            print(f"system {inventory_id} has manually_fixable_cve_list from vmaas-py which is not in vmaas-go: {manual_cves_py_not_in_go}")
                        if manual_cves_go_not_in_py:
                            print(f"system {inventory_id} has manually_fixable_cve_list from vmaas-go which is not in vmaas-py: {manual_cves_go_not_in_py}")

                        unpatched_cves_py = {cve["cve"] for cve in vulns_py["unpatched_cve_list"]}
                        unpatched_cves_go = {cve["cve"] for cve in vulns_go["unpatched_cve_list"]}
                        unpatched_cves_py_not_in_go = {cve for cve in unpatched_cves_py if cve not in unpatched_cves_go}
                        unpatched_cves_go_not_in_py = {cve for cve in unpatched_cves_go if cve not in unpatched_cves_py}            
                        if len(vulns_py["unpatched_cve_list"]) != len(vulns_go["unpatched_cve_list"]):
                            print(f"system {inventory_id} has unpatched_cve_list len {len(vulns_py['unpatched_cve_list'])} from vmaas-py")
                            print(f"system {inventory_id} has unpatched_cve_list len {len(vulns_go['unpatched_cve_list'])} from vmaas-go")
                        if unpatched_cves_py_not_in_go:
                            print(f"system {inventory_id} has unpatched_cve_list from vmaas-py which is not in vmaas-go: {unpatched_cves_py_not_in_go}")
                        if unpatched_cves_go_not_in_py:
                            print(f"system {inventory_id} has unpatched_cve_list from vmaas-go which is not in vmaas-py: {unpatched_cves_go_not_in_py}")

                    system = cur.fetchone()

            except sqlite3.DatabaseError as e:
                con.rollback()
                print("Error occured during querying DB: \"%s\"" % e)
    
    print("")
    print("Python durations:")
    s = pd.Series(durations_py)
    print(s.describe())

    print("")
    print("Go durations:")
    s = pd.Series(durations_go)
    print(s.describe())


if __name__ == "__main__":
    main()
