#!/usr/bin/env python3
"""Maintain Utils.kt VALID_CERTIFICATES (the APK signing-cert allowlist).

Subcommands:
  validate                      check the list is well-formed (40-hex lowercase, unique)
  import-apk <apk...>           report/import signer certs from local APKs
  check-fdroid <package-id...>  download APKs from f-droid.org and import their certs

A signer cert is only imported when the APK signature verifies AND either its
rotation lineage contains an already-allowlisted cert (a key rotation of a
trusted vendor, proven by the old key's signature) or --trust-new is given
(new vendor, vetted by a human or by the download source).

Requires apksigner (Android build-tools); pass --apksigner or set ANDROID_HOME.
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

UTILS_KT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src/main/java/org/osservatorionessuno/libmvt/common/Utils.kt",
)
FDROID_API = "https://f-droid.org/api/v1/packages/%s"
FDROID_REPO = "https://f-droid.org/repo/%s_%d.apk"


def find_apksigner(override=None):
    if override:
        return override
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(env)
        if not root:
            continue
        candidates = sorted(glob.glob(os.path.join(root, "build-tools", "*", "apksigner")))
        if candidates:
            return candidates[-1]
    return "apksigner"  # hope it's on PATH


def read_allowlist():
    """Return (full_text, block_start, block_end, {sha1: line}) for VALID_CERTIFICATES."""
    text = open(UTILS_KT).read()
    start = text.index("val VALID_CERTIFICATES")
    end = start + re.search(r"\n\s*\)", text[start:]).start()
    entries = {}
    for m in re.finditer(r'"([0-9a-fA-F]{40})"[^\n]*', text[start:end]):
        entries[m.group(1)] = m.group(0)
    return text, start, end, entries


def cmd_validate(_args):
    text, start, end, entries = read_allowlist()
    block = text[start:end]
    quoted = re.findall(r'"([^"]*)"', block)
    bad = [q for q in quoted if not re.fullmatch(r"[0-9a-f]{40}", q)]
    dupes = sorted({q for q in quoted if quoted.count(q) > 1})
    if bad:
        print("malformed entries (must be 40-char lowercase hex): %s" % bad)
    if dupes:
        print("duplicate entries: %s" % dupes)
    if bad or dupes:
        return 1
    print("VALID_CERTIFICATES ok: %d entries" % len(entries))
    return 0


def apksigner_certs(apksigner, apk):
    """Return (verified, [(sha1, dn)] signers, [sha1] lineage)."""
    proc = subprocess.run([apksigner, "verify", "--print-certs", apk],
                          capture_output=True, text=True)
    out = proc.stdout
    verified = proc.returncode == 0
    # "Signer ..." lines only: "Source Stamp Signer ..." certs are not APK signers.
    signers = list(zip(
        [s.lower() for s in re.findall(r"^Signer .*?certificate SHA-1 digest: ([0-9a-f]{40})", out, re.M)],
        re.findall(r"^Signer .*?certificate DN: ([^\n]+)", out, re.M) or [""] * 10,
    ))
    lin = subprocess.run([apksigner, "lineage", "--print-certs", "--in", apk],
                         capture_output=True, text=True).stdout
    lineage = [s.lower() for s in re.findall(r"certificate SHA-1 digest: ([0-9a-f]+)", lin)]
    return verified, signers, lineage


def entry_comment(dn):
    m = re.search(r"CN=([^,]+)", dn)
    return (m.group(1) if m else dn or "unknown").strip()


def import_apks(apks, apksigner, update, trust_new):
    text, start, end, allow = read_allowlist()
    additions = []
    failed = False
    for apk in apks:
        verified, signers, lineage = apksigner_certs(apksigner, apk)
        name = os.path.basename(apk)
        if not verified:
            print("SKIP %s: signature does not verify" % name)
            failed = True
            continue
        rotation_trusted = any(c in allow for c in lineage)
        for sha1, dn in signers:
            if sha1 in allow or sha1 in [a[0] for a in additions]:
                print("OK   %s: %s already allowlisted" % (name, sha1))
            elif rotation_trusted or trust_new:
                why = "rotation from allowlisted cert" if rotation_trusted else "trust-new"
                print("ADD  %s: %s (%s; %s)" % (name, sha1, entry_comment(dn), why))
                additions.append((sha1, entry_comment(dn)))
            else:
                print("HOLD %s: %s (%s) — no allowlisted lineage; re-run with --trust-new to import"
                      % (name, sha1, entry_comment(dn)))
                failed = True
    if additions and update:
        lines = "".join('\t\t"%s", // %s\n' % (sha1, comment) for sha1, comment in additions)
        insert_at = end + 1  # end sits on the newline before the closing parenthesis
        open(UTILS_KT, "w").write(text[:insert_at] + lines + text[insert_at:])
        print("updated %s with %d entries" % (UTILS_KT, len(additions)))
    elif additions:
        print("%d new certs found; re-run with --update to write Utils.kt" % len(additions))
    return 1 if failed else 0


def cmd_import_apk(args):
    return import_apks(args.apk, find_apksigner(args.apksigner), args.update, args.trust_new)


def cmd_check_fdroid(args):
    apks = []
    tmp = tempfile.mkdtemp(prefix="fdroid-certs-")
    for pkg in args.package:
        meta = json.load(urllib.request.urlopen(FDROID_API % pkg, timeout=60))
        url = FDROID_REPO % (pkg, meta["suggestedVersionCode"])
        dest = os.path.join(tmp, "%s.apk" % pkg)
        print("fetching %s" % url)
        urllib.request.urlretrieve(url, dest)
        apks.append(dest)
    # f-droid.org over TLS is the vetting for new certs here.
    return import_apks(apks, find_apksigner(args.apksigner), args.update, trust_new=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate").set_defaults(func=cmd_validate)
    imp = sub.add_parser("import-apk")
    imp.add_argument("apk", nargs="+")
    imp.add_argument("--update", action="store_true", help="write new entries to Utils.kt")
    imp.add_argument("--trust-new", action="store_true",
                     help="import certs with no allowlisted lineage (new vendors)")
    imp.add_argument("--apksigner")
    imp.set_defaults(func=cmd_import_apk)
    fd = sub.add_parser("check-fdroid")
    fd.add_argument("package", nargs="+")
    fd.add_argument("--update", action="store_true", help="write new entries to Utils.kt")
    fd.add_argument("--apksigner")
    fd.set_defaults(func=cmd_check_fdroid)
    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
