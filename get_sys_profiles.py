#!/usr/bin/env python3

import math
import os
import sqlite3
import sys
import requests

GABI_URL = os.getenv("GABI_URL", "")
GABI_TOKEN = os.getenv("GABI_TOKEN", "")

HEADERS = {"Authorization": f"Bearer {GABI_TOKEN}"}

TABLES = {
    "system":
        """
        CREATE TABLE IF NOT EXISTS system (
            inventory_id TEXT NOT NULL UNIQUE,
            vmaas_json TEXT NOT NULL
        )
        """
}


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


def query(query):
    tries = 0
    data = {"query": query}
    while tries <= 5:
        r = requests.post(GABI_URL, headers=HEADERS, json=data)
        if r.status_code == 200:
            return r.json()["result"]
        else:
            print(f"Query failed: {query}, HTTP code: {r.status_code}", file=sys.stderr)
            tries += 1
    sys.exit(3)


def main():
    if not GABI_URL or not GABI_TOKEN:
        print("GABI_URL or GABI_TOKEN env variable not defined!", file=sys.stderr)
        sys.exit(1)
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <sqlite_file>", file=sys.stderr)
        sys.exit(2)
    sqlite_file = sys.argv[1]

    print(f"Gabi URL: {GABI_URL}")
    print(f"Gabi token: ***")
    print("")

    with SqliteConnection(sqlite_file) as con:
        with SqliteCursor(con) as cur:
            try:
                for table, sql in TABLES.items():
                    print("Ensuring table exists: %s" % table)
                    cur.execute(sql)
                con.commit()
                print("DB schema initialization completed")

                number_of_sys = int(query(f"SELECT COUNT(*) FROM system_platform;")[1][0])
                print(f"Systems: {number_of_sys}")

                pages = math.floor(number_of_sys/100)
                for i in range(9700,pages):
                    chunk = query(f"SELECT inventory_id, vmaas_json FROM system_platform ORDER BY id LIMIT 100 OFFSET {i*100};")
                    cur.executemany("INSERT INTO system (inventory_id, vmaas_json) VALUES (?, ?) ON CONFLICT DO NOTHING", chunk[1:])
                    con.commit()
                    print(f"{i+1}/{pages} done")

            except sqlite3.DatabaseError as e:
                con.rollback()
                print("Error occured during populating DB: \"%s\"" % e)


if __name__ == "__main__":
    main()
