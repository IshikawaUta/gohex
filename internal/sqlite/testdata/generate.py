#!/usr/bin/env python3
"""Regenerate the on-disk fixtures used by package sqlite tests.

The fixtures are committed so `go test ./internal/sqlite/...` needs no
external tool. This script only documents how they were produced; it needs
python3 with the stdlib sqlite3 module.

    python3 internal/sqlite/testdata/generate.py

Assertions in sqlite_test.go compare against the values written here, so if
you change the data you must change the tests too.

Not generated here: *-wal and *-journal companions are written while the
connection is still open, which is the only way to get a WAL/journal that
SQLite has not already checkpointed away.
"""

import os
import shutil
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

UNICODE = "Bahasa Indonesia — 日本語 ✅ naïve résumé\nwith a newline, 'quotes' and \"double\""


def connect(name, page_size=1024, encoding="UTF-8"):
    path = os.path.join(HERE, name)
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size=%d" % page_size)
    con.execute("PRAGMA encoding='%s'" % encoding)
    return con, path


def basic():
    con, path = connect("basic.db")
    con.executescript(
        """
        CREATE TABLE urls(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          url LONGVARCHAR,
          title LONGVARCHAR,
          visit_count INTEGER DEFAULT 0 NOT NULL,
          typed_count INTEGER DEFAULT 0 NOT NULL,
          last_visit_time INTEGER NOT NULL,
          hidden INTEGER DEFAULT 0 NOT NULL);
        CREATE TABLE visits(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          url INTEGER NOT NULL,
          visit_time INTEGER NOT NULL,
          from_visit INTEGER,
          transition INTEGER DEFAULT 0 NOT NULL,
          visit_duration INTEGER DEFAULT 0 NOT NULL);
        CREATE TABLE "odd names"(
          "quoted col" INTEGER,
          [bracket col] TEXT,
          `backtick col` TEXT,
          c INTEGER CHECK (c > 0),
          d TEXT DEFAULT 'x');
        CREATE TABLE pk(k TEXT PRIMARY KEY, n INTEGER) WITHOUT ROWID;
        CREATE TABLE blobs(b INTEGER PRIMARY KEY, data BLOB, f REAL, n TEXT);
        CREATE VIEW v_urls AS SELECT id, url FROM urls;
        CREATE INDEX i_visits ON visits(visit_time);
        """
    )
    long_title = "long-" + ("0123456789abcdef" * 400)  # 6400 bytes: forces overflow
    rows = []
    for i in range(1, 401):
        title = long_title if i == 7 else (UNICODE if i % 5 == 0 else "title %d" % i)
        rows.append(
            (
                "https://example.test/%d" % i,
                title,
                i % 97,
                i % 3,
                1000000 + i * 1000,
                1 if i % 11 == 0 else 0,
            )
        )
    con.executemany(
        "INSERT INTO urls(url, title, visit_count, typed_count, last_visit_time, hidden)"
        " VALUES (?,?,?,?,?,?)",
        rows,
    )
    con.executemany(
        "INSERT INTO visits(url, visit_time, from_visit, transition, visit_duration)"
        " VALUES (?,?,?,?,?)",
        [
            ((i - 1) % 400 + 1, 2000000 + i, i - 1 if i > 1 else None, i % 8, i * 500)
            for i in range(1, 801)
        ],
    )
    con.executemany(
        "INSERT INTO \"odd names\"(\"quoted col\", [bracket col], `backtick col`, c) VALUES (?,?,?,?)",
        [(1, "a", "b", 10), (-2, None, "ссылка", 20)],
    )
    con.executemany(
        "INSERT INTO pk(k, n) VALUES (?,?)",
        [("alpha", 1), ("beta", 2), ("gamma", None)],
    )
    con.executemany(
        "INSERT INTO blobs(b, data, f, n) VALUES (?,?,?,?)",
        [
            (1, b"", None, None),
            (2, bytes(range(256)), -1.5, "real null mix"),
            (3, b"\x00\xff\xfe", 0.0, ""),
            (4, None, 3.25, UNICODE),
        ],
    )
    con.commit()
    con.close()
    return path


def utf16():
    con, path = connect("utf16.db", page_size=1024, encoding="UTF-16le")
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT)")
    con.executemany("INSERT INTO t(s) VALUES (?)", [(UNICODE,), ("plain ascii",), (None,)])
    con.commit()
    con.close()
    return path


def empty():
    con, path = connect("empty.db", page_size=4096)
    con.execute("PRAGMA user_version=1")
    con.commit()
    con.close()
    return path


def wal():
    """A database whose rows exist only in the write-ahead log.

    The connection is left open while the files are copied, otherwise SQLite
    checkpoints and deletes the WAL on close.
    """
    path = os.path.join(HERE, "wal.db")
    work = os.path.join(HERE, "_wal_work.db")
    for suffix in ("", "-wal", "-shm"):
        for base in (path, work):
            if os.path.exists(base + suffix):
                os.remove(base + suffix)
    con = sqlite3.connect(work)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA page_size=4096")
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT)")
    for i in range(50):
        con.execute("INSERT INTO t(s) VALUES (?)", ("wal-row-%d" % i,))
    con.commit()
    shutil.copyfile(work, path)
    shutil.copyfile(work + "-wal", path + "-wal")
    con.close()
    for suffix in ("", "-wal", "-shm"):
        drop(work, suffix)
    return path


def drop(path, suffix):
    if os.path.exists(path + suffix):
        os.remove(path + suffix)


def main():
    made = [basic(), utf16(), empty(), wal()]
    for p in made[:-1]:
        for suffix in ("-wal", "-shm", "-journal"):
            drop(p, suffix)
    drop(made[-1], "-shm")
    drop(made[-1], "-journal")
    for p in made:
        print("%-16s %7d bytes" % (os.path.basename(p), os.path.getsize(p)))
    print("%-16s %7d bytes" % ("wal.db-wal", os.path.getsize(made[-1] + "-wal")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
