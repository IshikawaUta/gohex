#!/usr/bin/env python3
"""Generate the committed browser fixtures under internal/browser/testdata.

The fixtures are checked in so the Go tests never depend on a browser or on
the sqlite3 CLI being installed (CI would otherwise skip them and drag the
coverage figure below the gate). Regenerate with:

    python3 internal/browser/testdata/generate.py

Each database is built with the schema its browser really writes, on the
subset of tables the reader uses, plus the columns the reader must cope with
being absent (Safari's history_items has no title column, for instance).

The Chrome History file is left in WAL mode with the log still uncheckpointed
on purpose: that is how a live browser leaves the file, and the reader has to
merge the log itself.
"""

import json
import os
import shutil
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))

# Shared reference instant: 2024-01-15T12:00:00Z.
UNIX_US = 1_705_320_000_000_000
CHROME_US = UNIX_US + 11_644_473_600_000_000  # microseconds since 1601-01-01
SAFARI_S = 1_705_320_000 - 978_307_200  # seconds since 2001-01-01


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)
    return path


def build_chrome():
    """Chrome/Chromium/Edge/Brave History plus the Bookmarks JSON file."""
    target_dir = os.path.join(HERE, "chrome", "Default")
    os.makedirs(target_dir, exist_ok=True)
    raw = os.path.join(target_dir, "History.raw")
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(raw + suffix)
        except FileNotFoundError:
            pass

    conn = sqlite3.connect(raw)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url LONGVARCHAR,
            title TEXT,
            visit_count INTEGER DEFAULT 0 NOT NULL,
            typed_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL,
            hidden INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER,
            transition INTEGER DEFAULT 0 NOT NULL,
            segment_id INTEGER,
            visit_duration INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE downloads (
            id INTEGER PRIMARY KEY,
            guid TEXT NOT NULL,
            current_path TEXT NOT NULL,
            target_path TEXT NOT NULL,
            start_time INTEGER NOT NULL,
            received_bytes INTEGER DEFAULT 0 NOT NULL,
            total_bytes INTEGER DEFAULT 0 NOT NULL,
            state INTEGER DEFAULT 0 NOT NULL,
            interrupt_reason INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE downloads_url_chains (
            id INTEGER PRIMARY KEY,
            download_id INTEGER NOT NULL,
            chain_index INTEGER NOT NULL,
            url TEXT NOT NULL
        );
        """
    )
    conn.executemany(
        "INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [
            (1, "https://example.com/", "Example Domain", 5, 2, CHROME_US),
            (2, "https://go.dev/", "Go", 3, 1, CHROME_US - 3_600_000_000),
            # A row the browser emptied: no timestamp worth reporting.
            (3, "https://internal.local/doc", "", 1, 0, 0),
        ],
    )
    conn.executemany(
        "INSERT INTO downloads (id, guid, current_path, target_path, start_time,"
        " received_bytes, total_bytes, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, "g1", "/home/analyst/Downloads/report.pdf",
             "/home/analyst/Downloads/report.pdf", CHROME_US, 1024, 2048, 1),
            (2, "g2", "", "/tmp/partial.zip", CHROME_US, 100, 0, 0),
            (3, "g3", "/tmp/cancelled.bin", "/tmp/cancelled.bin",
             CHROME_US - 60_000_000, 0, 4096, 2),
        ],
    )
    conn.executemany(
        "INSERT INTO downloads_url_chains (id, download_id, chain_index, url)"
        " VALUES (?, ?, ?, ?)",
        [
            (1, 1, 0, "https://example.com/report.pdf"),
            # A second link in the chain: a redirect the reader must ignore,
            # otherwise the reported source URL would be the wrong one.
            (2, 1, 1, "https://mirror.example.com/report.pdf"),
            (3, 2, 0, "https://cdn.example.com/partial.zip"),
            (4, 3, 0, "https://example.com/cancelled.bin"),
        ],
    )
    conn.commit()

    # Copy the database and its log out while the connection still holds the
    # log open: closing first would checkpoint the log away and delete it,
    # leaving a fixture that proves nothing.
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    if mode.lower() != "wal":
        raise SystemExit("journal_mode is %r, not WAL" % mode)
    shutil.copyfile(raw, os.path.join(target_dir, "History"))
    shutil.copyfile(raw + "-wal", os.path.join(target_dir, "History-wal"))
    conn.close()
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(raw + suffix)
        except FileNotFoundError:
            pass

    bookmarks = {
        "checksum": "fixture",
        "roots": {
            "bookmark_bar": {
                "type": "folder",
                "name": "Bookmarks bar",
                "date_added": str(CHROME_US),
                "children": [
                    {
                        "type": "folder",
                        "name": "News",
                        "date_added": str(CHROME_US),
                        "children": [
                            {
                                "type": "url",
                                "name": "Go Blog",
                                "url": "https://go.dev/blog/",
                                "date_added": str(CHROME_US),
                            }
                        ],
                    },
                    {
                        "type": "url",
                        "name": "Example",
                        "url": "https://example.com/",
                        "date_added": str(CHROME_US),
                    },
                ],
            },
            "other": {
                "type": "folder",
                "name": "Other bookmarks",
                "date_added": "0",
                "children": [],
            },
        },
        "version": 1,
    }
    write(
        os.path.join(target_dir, "Bookmarks"),
        json.dumps(bookmarks, indent=2, sort_keys=True) + "\n",
    )
    print("chrome/Default/History + Bookmarks")


def build_firefox():
    """Firefox places.sqlite: history, bookmark tree and download annotations."""
    path = os.path.join(HERE, "firefox", "abcd1234.default-release", "places.sqlite")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            os.unlink(path + suffix)
        except FileNotFoundError:
            pass

    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url LONGVARCHAR,
            title LONGVARCHAR,
            rev_host LONGVARCHAR,
            visit_count INTEGER DEFAULT 0,
            hidden INTEGER DEFAULT 0 NOT NULL,
            typed INTEGER DEFAULT 0 NOT NULL,
            frecency INTEGER DEFAULT -1 NOT NULL,
            last_visit_date INTEGER,
            guid TEXT,
            foreign_count INTEGER DEFAULT 0 NOT NULL,
            url_hash INTEGER DEFAULT 0 NOT NULL,
            origin_id INTEGER
        );
        CREATE TABLE moz_bookmarks (
            id INTEGER PRIMARY KEY,
            type INTEGER,
            fk INTEGER,
            parent INTEGER,
            position INTEGER,
            title TEXT,
            keyword_id INTEGER,
            folder_type TEXT,
            dateAdded INTEGER,
            lastModified INTEGER,
            syncStatus INTEGER DEFAULT 1,
            syncChangeCounter INTEGER DEFAULT 1
        );
        CREATE TABLE moz_anno_attributes (
            id INTEGER PRIMARY KEY,
            name VARCHAR(32) NOT NULL,
            flags INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE moz_annos (
            id INTEGER PRIMARY KEY,
            place_id INTEGER NOT NULL,
            anno_attribute_id INTEGER,
            content LONGVARCHAR,
            flags INTEGER DEFAULT 0,
            expiration INTEGER DEFAULT 0,
            type INTEGER DEFAULT 0,
            dateAdded INTEGER DEFAULT 0,
            lastModified INTEGER DEFAULT 0
        );
        """
    )
    conn.executemany(
        "INSERT INTO moz_places (id, url, title, visit_count, typed, last_visit_date)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [
            (1, "https://mozilla.org/", "Mozilla", 4, 1, UNIX_US),
            (2, "https://example.org/", "", 1, 0, None),
            (3, "https://dl.example.com/a.zip", "a.zip", 1, 0, UNIX_US),
            (4, "https://dl.example.com/b.7z", "b.7z", 1, 0, UNIX_US),
        ],
    )
    conn.executemany(
        "INSERT INTO moz_anno_attributes (id, name, flags) VALUES (?, ?, 0)",
        [
            (1, "downloads/destinationFileURI"),
            (2, "downloads/metaData"),
            # An annotation the reader must not mistake for a download.
            (3, "bookmarkSync"),
        ],
    )
    conn.executemany(
        "INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded)"
        " VALUES (?, ?, ?, ?)",
        [
            (3, 1, "file:///home/analyst/Downloads/a.zip", UNIX_US),
            (3, 2, json.dumps(
                {"state": 1, "deleted": False, "endTime": UNIX_US // 1000 + 60_000,
                 "fileSize": 1024}
            ), UNIX_US),
            (4, 1, "file:///home/analyst/Downloads/b.7z", UNIX_US),
            (4, 2, json.dumps(
                {"state": 2, "deleted": False, "endTime": UNIX_US // 1000 + 5_000}
            ), UNIX_US),
            (1, 3, "sync-token", UNIX_US),
        ],
    )
    conn.executemany(
        "INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, dateAdded)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 2, None, 0, 0, "root", UNIX_US),
            (2, 2, None, 1, 0, "Bookmarks Menu", UNIX_US),
            (3, 2, None, 2, 0, "News", UNIX_US),
            (4, 1, 1, 3, 0, "Mozilla", UNIX_US),
            (5, 1, 2, 2, 1, "Example", UNIX_US),
            # A tag container (type 3) must be skipped, not mislabelled.
            (6, 3, None, 0, 1, "tags", UNIX_US),
            # A bookmark whose place row is gone: skipped, not crashed on.
            (7, 1, 99, 2, 2, "Orphan", UNIX_US),
        ],
    )
    conn.commit()
    conn.close()
    print("firefox/abcd1234.default-release/places.sqlite")


def build_safari():
    """Safari History.db: history_items joined to history_visits in the reader."""
    path = os.path.join(HERE, "safari", "Library", "Safari", "History.db")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            os.unlink(path + suffix)
        except FileNotFoundError:
            pass

    conn = sqlite3.connect(path)
    conn.executescript(
        """
        -- No title column: Safari keeps titles on the visits instead.
        CREATE TABLE history_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            domain_expansion TEXT,
            visit_count INTEGER NOT NULL,
            daily_visit_counts BLOB,
            weekly_visit_counts BLOB,
            autocomplete_triggers TEXT,
            should_recompute_derived_visit_counts INTEGER,
            visit_count_score INTEGER NOT NULL DEFAULT 0,
            status_code INTEGER DEFAULT 0
        );
        CREATE TABLE history_visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_item INTEGER NOT NULL REFERENCES history_items(id) ON DELETE CASCADE,
            visit_time REAL NOT NULL,
            title TEXT,
            load_successful BOOLEAN NOT NULL DEFAULT 1,
            http_non_get BOOLEAN NOT NULL DEFAULT 0,
            synthesized BOOLEAN NOT NULL DEFAULT 0,
            redirect_source INTEGER,
            redirect_destination INTEGER,
            origin INTEGER NOT NULL DEFAULT 0,
            generation INTEGER NOT NULL DEFAULT 0,
            attributes INTEGER NOT NULL DEFAULT 0,
            score INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    conn.executemany(
        "INSERT INTO history_items (id, url, visit_count) VALUES (?, ?, ?)",
        [
            (1, "https://apple.com/", 2),
            (2, "https://news.ycombinator.com/", 2),
            (3, "https://empty.example/", 0),
        ],
    )
    conn.executemany(
        "INSERT INTO history_visits (id, history_item, visit_time, title)"
        " VALUES (?, ?, ?, ?)",
        [
            (1, 1, SAFARI_S - 360.0, "Apple - older"),
            (2, 1, SAFARI_S, "Apple"),
            (3, 2, SAFARI_S - 2_800.5, "Hacker News"),
            # The newest visit carries no title; the earlier one does and
            # must be kept rather than replaced with an empty string.
            (4, 2, SAFARI_S - 1_000.0, ""),
            # An orphan visit pointing at a row that no longer exists.
            (5, 99, SAFARI_S, "Ghost"),
        ],
    )
    conn.commit()
    conn.close()
    print("safari/Library/Safari/History.db")


def build_chrome_partial():
    """A Chromium History file that has drifted: no downloads table at all.

    Browsers rename and drop columns between versions, and a reader that
    treats a missing table as fatal would throw away the history it just
    read. This fixture is a plain (non-WAL) database so the reader is also
    exercised on the other journal mode.
    """
    path = os.path.join(HERE, "chrome_partial", "Default", "History")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            os.unlink(path + suffix)
        except FileNotFoundError:
            pass

    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url LONGVARCHAR,
            title TEXT,
            visit_count INTEGER DEFAULT 0 NOT NULL,
            typed_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL
        );
        """
    )
    conn.execute(
        "INSERT INTO urls (id, url, title, visit_count, typed_count,"
        " last_visit_time) VALUES (1, ?, ?, 2, 1, ?)",
        ("https://only.example/", "Only", CHROME_US),
    )
    conn.commit()
    conn.close()
    print("chrome_partial/Default/History")


if __name__ == "__main__":
    build_chrome()
    build_firefox()
    build_safari()
    build_chrome_partial()
