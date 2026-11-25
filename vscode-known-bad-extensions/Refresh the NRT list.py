#!/usr/bin/env python3
"""Refresh the list of extension IDs inside the two NRT rules.

A Continuous (NRT) rule can't download a list, so the IDs are written into the query.
This script rebuilds that block from VSXSentry's malicious feed. An ID gets in only if:

  1. Microsoft removed it from the Marketplace as malware, and
  2. it has been on Microsoft's list for at least 21 days, and
  3. it isn't one of the real extensions named in RealProducts in the main rule.

Usage:
  python3 "Refresh the NRT list.py"                   download the feed and refresh
  python3 "Refresh the NRT list.py" --feed copy.csv   use a copy you already have
  python3 "Refresh the NRT list.py" --check           show what would change, write nothing

It stops without writing anything if an ID has an odd shape, or if the list would move
by more than --max-change IDs (default 100). These IDs can isolate a device, so read
the diff before you commit it. It only uses Python's standard library.
"""
import argparse
import csv
import datetime
import io
import pathlib
import re
import sys
import urllib.request

FEED_URL = "https://vsxsentry.github.io/feeds/vsxsentry_malicious_feed.csv"
HERE = pathlib.Path(__file__).resolve().parent
MAIN_RULE = HERE / "Known bad VS Code extension on a device.kql"
NRT_RULES = [
    HERE / "Known malware VS Code extension, file activity (NRT).kql",
    HERE / "Known malware VS Code extension, process activity (NRT).kql",
]
LIST_START = "| where ExtensionId in ("
LIST_END = "    )"
# Lowercase publisher.name and nothing else. Anything outside this could break out of the
# quoted list in the query, so one bad ID stops the whole run.
ID_SHAPE = re.compile(r"[a-z0-9][a-z0-9_-]*\.[a-z0-9][a-z0-9._-]*")
NEEDED_COLUMNS = ("extension_id", "metadata_category", "metadata_status", "removal_date")


def stop(message):
    sys.exit(f"Stopped, nothing written: {message}")


def read_feed(source):
    if source:
        raw = pathlib.Path(source).read_bytes()
    else:
        request = urllib.request.Request(FEED_URL, headers={"User-Agent": "refresh-nrt-list"})
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8"), newline="")))
    if not rows or any(column not in rows[0] for column in NEEDED_COLUMNS):
        stop("the feed doesn't have the columns this script reads.")
    return rows


def real_products():
    text = MAIN_RULE.read_text(encoding="utf-8")
    found = re.search(r"let RealProducts = dynamic\(\[(.*?)\]\);", text, re.S)
    if not found:
        stop("couldn't find RealProducts in the main rule.")
    return set(re.findall(r'"([^"]+)"', found.group(1)))


def pick_ids(rows, soak_days, today):
    skip = real_products()
    keep, too_new = set(), 0
    for row in rows:
        if "removed_marketplace" not in row["metadata_status"]:
            continue
        if "malware" not in row["metadata_category"].lower():
            continue
        extension_id = row["extension_id"].strip().lower()
        if not ID_SHAPE.fullmatch(extension_id):
            stop(f"this ID has a shape I don't trust: {row['extension_id']!r}")
        if extension_id in skip:
            continue
        try:
            removed_on = datetime.date.fromisoformat(row["removal_date"].strip())
        except ValueError:
            stop(f"{extension_id} has no usable removal date: {row['removal_date']!r}")
        if (today - removed_on).days < soak_days:
            too_new += 1
            continue
        keep.add(extension_id)
    return sorted(keep), too_new


def find_list(lines, path):
    if lines.count(LIST_START) != 1:
        stop(f"{path.name} doesn't have exactly one '{LIST_START}' line.")
    start = lines.index(LIST_START)
    if LIST_END not in lines[start:]:
        stop(f"{path.name} has no closing line for the ID list.")
    end = lines.index(LIST_END, start)
    old = []
    for line in lines[start + 1:end]:
        entry = re.fullmatch(r'    "([^"]+)",?', line)
        if not entry:
            stop(f"{path.name} has a line in the ID list I can't read: {line!r}")
        old.append(entry.group(1))
    return start, end, old


def main():
    parser = argparse.ArgumentParser(description="Refresh the list of extension IDs inside the two NRT rules.")
    parser.add_argument("--feed", help="path to a copy of vsxsentry_malicious_feed.csv (default: download it)")
    parser.add_argument("--soak-days", type=int, default=21, help="days an ID must have been on Microsoft's list (default 21)")
    parser.add_argument("--max-change", type=int, default=100, help="stop if more IDs than this are added or removed (default 100)")
    parser.add_argument("--today", help="pretend today is this date, YYYY-MM-DD (for testing)")
    parser.add_argument("--check", action="store_true", help="show what would change and write nothing")
    args = parser.parse_args()
    today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()

    ids, too_new = pick_ids(read_feed(args.feed), args.soak_days, today)
    if not ids:
        stop("the feed gave me no IDs at all.")

    plans = []
    for path in NRT_RULES:
        lines = path.read_text(encoding="utf-8").split("\n")
        start, end, old = find_list(lines, path)
        added, removed = sorted(set(ids) - set(old)), sorted(set(old) - set(ids))
        if len(added) + len(removed) > args.max_change:
            stop(f"{path.name} would gain {len(added)} IDs and lose {len(removed)}. That's more than "
                 f"--max-change {args.max_change}. Check the feed, then rerun with a higher number if it's right.")
        block = [f'    "{extension_id}",' for extension_id in ids]
        block[-1] = block[-1].rstrip(",")
        plans.append((path, "\n".join(lines[:start + 1] + block + lines[end:]), added, removed))

    for path, text, added, removed in plans:
        print(f"{path.name}: {len(ids)} IDs, {len(added)} added, {len(removed)} removed")
        for extension_id in added[:40]:
            print(f"  + {extension_id}")
        for extension_id in removed[:40]:
            print(f"  - {extension_id}")
        if len(added) > 40 or len(removed) > 40:
            print("  (only the first 40 of each are shown; git diff has the rest)")
        if not args.check:
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
    print(f"{too_new} newer IDs are waiting out the {args.soak_days} days.")
    print("Nothing was written (--check)." if args.check else "Done. Read the git diff before you commit.")


if __name__ == "__main__":
    main()
