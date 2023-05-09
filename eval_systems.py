#!/usr/bin/env python3

import math
import os
import sqlite3
import sys
import requests
import json
import re

VMAAS_URL = "http://localhost:8080/api/vmaas/v3/vulnerabilities"

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

    playbook_cves_stats = []
    manual_cves_stats = []
    unfixed_cves_stats = []
    unfixed_packages_stats = []
    total_packages_stats = []

    with SqliteConnection(sqlite_file) as con:
        with SqliteCursor(con) as cur:
            try:
                cur.execute(f"SELECT inventory_id, vmaas_json FROM system ORDER by inventory_id LIMIT {system_limit}")
                system = cur.fetchone()
                while system:
                    inventory_id, vmaas_json = system
                    if vmaas_json == "":
                        system = cur.fetchone()
                        continue
                    vmaas_json = json.loads(vmaas_json)
                    vmaas_json["extended"] = True
                    total_packages = len(vmaas_json["package_list"])
                    repository_list = [repo for repo in vmaas_json.get('repository_list', []) if repo.startswith("rhel")]
                    resp = requests.post(VMAAS_URL, json=vmaas_json)
                    if resp.status_code != 200:
                        system = cur.fetchone()
                        continue
                    vulns = resp.json()
                    playbook_cves = len(vulns['cve_list'])
                    manual_cves = len(vulns['manually_fixable_cve_list'])
                    unfixed_cves = len(vulns['unpatched_cve_list'])
                    unfixed_breakdown = {}
                    for unfixed_cve in vulns['unpatched_cve_list']:
                        for affected_package in unfixed_cve['affected_packages']:
                            nevra = parse_rpm_name(affected_package)
                            name = nevra[0]
                            if name not in unfixed_breakdown:
                                unfixed_breakdown[name] = 0
                            unfixed_breakdown[name] += 1
                    unfixed_breakdown = tuple(unfixed_breakdown.items())
                    unfixed_packages = len(unfixed_breakdown)
                    print(f"{inventory_id}: " \
                            f"repos={repository_list}, " \
                            f"playbook_cves={playbook_cves}, " \
                            f"manual_cves={manual_cves}, " \
                            f"unfixed_cves={unfixed_cves}, " \
                            f"unfixed_pkgs={unfixed_packages}, " \
                            f"total_pkgs={total_packages}, " \
                            f"unfixed_pkgs_breakdown={sorted(unfixed_breakdown, key=lambda x: x[1], reverse=True)}" \
                            )
                    playbook_cves_stats.append(playbook_cves)
                    manual_cves_stats.append(manual_cves)
                    unfixed_cves_stats.append(unfixed_cves)
                    unfixed_packages_stats.append(unfixed_packages)
                    total_packages_stats.append(total_packages)
                    system = cur.fetchone()

            except sqlite3.DatabaseError as e:
                con.rollback()
                print("Error occured during querying DB: \"%s\"" % e)

            print("")
            print(f"total playbook cves: {sum(playbook_cves_stats)}")
            print(f"average playbook cves per system: {sum(playbook_cves_stats)/len(playbook_cves_stats)}")
            print(f"total manual cves: {sum(manual_cves_stats)}")
            print(f"average manual cves per system: {sum(manual_cves_stats)/len(manual_cves_stats)}")
            print(f"total unfixed cves: {sum(unfixed_cves_stats)}")
            print(f"average unfixed cves per system: {sum(unfixed_cves_stats)/len(unfixed_cves_stats)}")
            print(f"total unfixed packages: {sum(unfixed_packages_stats)}")
            print(f"average unfixed packages per system: {sum(unfixed_packages_stats)/len(unfixed_packages_stats)}")
            print(f"total packages: {sum(total_packages_stats)}")
            print(f"average packages per system: {sum(total_packages_stats)/len(total_packages_stats)}")


if __name__ == "__main__":
    main()
