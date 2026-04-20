"""
verify.py  —  Tamper-Evident Logging System
============================================
Reads logs.json and verifies the integrity of every entry.

Detects:
  - Modified fields  (description, event_type, metadata, timestamp, etc.)
  - Deleted entries  (sequence gap + broken chain)
  - Reordered entries (sequence mismatch + broken chain)

Usage:
    python verify.py

Exit codes:
    0  — log is intact
    1  — tampering detected (or file missing)
"""

import hashlib
import json
import os
import sys

LOG_FILE   = "logs.json"
GENESIS_HASH = "0" * 64

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ──────────────────────────────────────────────────────────
#  Core
# ──────────────────────────────────────────────────────────

def _compute_hash(seq_id: int, timestamp: str, event_type: str,
                  description: str, metadata: dict, prev_hash: str) -> str:
    payload = json.dumps(
        {
            "sequence_id": seq_id,
            "timestamp":   timestamp,
            "event_type":  event_type,
            "description": description,
            "metadata":    metadata,
            "prev_hash":   prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _load() -> list[dict]:
    if not os.path.exists(LOG_FILE):
        return None   # signals "file missing"
    with open(LOG_FILE, "r") as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("entries", [])


def verify() -> dict:
    """
    Walk every entry and run three independent checks:

    1. Hash integrity  — recompute SHA-256 from stored fields; compare to stored entry_hash.
                         Any field modification (even one character) is caught here.

    2. Chain linkage   — each entry's prev_hash must equal the stored entry_hash of the
                         PREVIOUS entry. Deletion or insertion breaks this link.

    3. Sequence order  — sequence_id must increment by exactly 1.
                         Deletion creates a gap; reordering creates non-monotonic ids.

    Returns:
        {
          "file_missing": bool,
          "valid":        bool,
          "total":        int,
          "issues": [
              {
                "position":    int,   # 0-based index in the file
                "sequence_id": int,
                "type":        str,   # HASH_MISMATCH | CHAIN_BREAK | SEQUENCE_GAP
                "detail":      str,
              }
          ]
        }
    """
    entries = _load()

    if entries is None:
        return {"file_missing": True, "valid": False, "total": 0, "issues": []}

    issues = []
    expected_prev_hash = GENESIS_HASH
    expected_seq_id    = 1

    for pos, entry in enumerate(entries):
        seq_id      = entry.get("sequence_id")
        timestamp   = entry.get("timestamp",   "")
        event_type  = entry.get("event_type",  "")
        description = entry.get("description", "")
        metadata    = entry.get("metadata",    {})
        prev_hash   = entry.get("prev_hash",   "")
        stored_hash = entry.get("entry_hash",  "")

        # ── Check 1: sequence continuity ──────────────────
        if seq_id != expected_seq_id:
            issues.append({
                "position":    pos,
                "sequence_id": seq_id,
                "type":        "SEQUENCE_GAP",
                "detail": (
                    f"Expected sequence_id {expected_seq_id}, "
                    f"found {seq_id}. "
                    f"{'Entry/entries were deleted or reordered.' if seq_id > expected_seq_id else 'Entry was inserted or sequence is corrupted.'}"
                ),
            })

        # ── Check 2: chain linkage ─────────────────────────
        if prev_hash != expected_prev_hash:
            issues.append({
                "position":    pos,
                "sequence_id": seq_id,
                "type":        "CHAIN_BREAK",
                "detail": (
                    f"prev_hash does not match the hash of the previous entry. "
                    f"Expected …{expected_prev_hash[-16:]}, "
                    f"got …{prev_hash[-16:]}. "
                    f"An entry was likely deleted, inserted, or reordered before this position."
                ),
            })

        # ── Check 3: content integrity ─────────────────────
        recomputed = _compute_hash(seq_id, timestamp, event_type, description, metadata, prev_hash)
        if recomputed != stored_hash:
            issues.append({
                "position":    pos,
                "sequence_id": seq_id,
                "type":        "HASH_MISMATCH",
                "detail": (
                    f"Recomputed hash does not match stored entry_hash. "
                    f"One or more fields (description, event_type, timestamp, metadata) "
                    f"were modified after this entry was written."
                ),
            })

        # Advance using the STORED hash (attacker cannot silently change it
        # without breaking the next entry's chain link)
        expected_prev_hash = stored_hash
        expected_seq_id    = seq_id + 1 if isinstance(seq_id, int) else expected_seq_id + 1

    return {
        "file_missing": False,
        "valid":  len(issues) == 0,
        "total":  len(entries),
        "issues": issues,
    }


# ──────────────────────────────────────────────────────────
#  Display helpers
# ──────────────────────────────────────────────────────────

ISSUE_COLOR = {
    "HASH_MISMATCH": RED,
    "CHAIN_BREAK":   YELLOW,
    "SEQUENCE_GAP":  CYAN,
}

ISSUE_LABEL = {
    "HASH_MISMATCH": "CONTENT MODIFIED",
    "CHAIN_BREAK":   "CHAIN BROKEN    ",
    "SEQUENCE_GAP":  "SEQUENCE GAP    ",
}


def _print_entries():
    """Print a summary table of all entries in the log."""
    entries = _load()
    if not entries:
        return
    print(f"\n  {'SEQ':>4}  {'TIMESTAMP':<32} {'TYPE':<14} DESCRIPTION")
    print("  " + "─" * 90)
    for e in entries:
        seq  = str(e.get("sequence_id", "?")).rjust(4)
        ts   = e.get("timestamp", "?")[:26]
        et   = e.get("event_type", "?")[:13].ljust(14)
        desc = e.get("description", "?")[:55]
        print(f"  {seq}  {ts:<32} {et} {desc}")


def main():
    print()
    print(BOLD + "=" * 65 + RESET)
    print(BOLD + "  TAMPER-EVIDENT LOG VERIFIER" + RESET)
    print(BOLD + "=" * 65 + RESET)
    print(f"  Log file : {os.path.abspath(LOG_FILE)}")
    print()

    result = verify()

    # ── File missing ────────────────────────────────────
    if result["file_missing"]:
        print(RED + BOLD + "  [CRITICAL] logs.json not found." + RESET)
        print("  Run  python add_logs.py  first to create the log.")
        sys.exit(1)

    print(f"  Entries found : {result['total']}")

    _print_entries()

    print()
    print(BOLD + "─" * 65 + RESET)

    # ── Clean log ────────────────────────────────────────
    if result["valid"]:
        print()
        print(GREEN + BOLD + "  ✔  LOG INTEGRITY VERIFIED — No tampering detected." + RESET)
        print(GREEN + f"     All {result['total']} entries are intact and correctly chained." + RESET)
        print()
        sys.exit(0)

    # ── Tampered log ─────────────────────────────────────
    print()
    print(RED + BOLD + f"  ✘  TAMPERING DETECTED — {len(result['issues'])} issue(s) found." + RESET)
    print()

    for iss in result["issues"]:
        color  = ISSUE_COLOR.get(iss["type"], RED)
        label  = ISSUE_LABEL.get(iss["type"], iss["type"])
        pos    = iss["position"]
        seq    = iss["sequence_id"]
        detail = iss["detail"]

        print(color + BOLD + f"  [{label}]" + RESET)
        print(f"    Position in file : entry at index {pos} (0-based)")
        print(f"    sequence_id      : {seq}")
        print(f"    Detail           : {detail}")
        print()

    print(RED + "─" * 65 + RESET)
    print(RED + BOLD + "  LOG IS COMPROMISED. Do not trust its contents." + RESET)
    print(RESET)
    sys.exit(1)


if __name__ == "__main__":
    main()
