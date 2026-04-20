import hashlib
import json
import os
from datetime import datetime, timezone

LOG_FILE = "logs.json"
GENESIS_HASH = "0" * 64


# ---------------- CORE ----------------
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


def _load():
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r") as f:
        data = json.load(f)

    return data if isinstance(data, list) else data.get("entries", [])


def _save(entries):
    with open(LOG_FILE, "w") as f:
        json.dump(entries, f, indent=2)


def add_log(event_type, description, metadata=None):

    if metadata is None:
        metadata = {}

    entries = _load()

    prev_hash = entries[-1]["entry_hash"] if entries else GENESIS_HASH
    seq_id    = entries[-1]["sequence_id"] + 1 if entries else 1
    timestamp = datetime.now(timezone.utc).isoformat()

    entry_hash = _compute_hash(seq_id, timestamp, event_type, description, metadata, prev_hash)

    entry = {
        "sequence_id": seq_id,
        "timestamp":   timestamp,
        "event_type":  event_type,
        "description": description,
        "metadata":    metadata,
        "prev_hash":   prev_hash,
        "entry_hash":  entry_hash,
    }

    entries.append(entry)
    _save(entries)

    print(f"\n[+] Entry {seq_id} added successfully")
    print(f"    Hash: {entry_hash[:16]}...\n")

    return entry


# ---------------- MAIN ----------------
if __name__ == "__main__":

    print("=" * 60)
    print("  TAMPER-EVIDENT LOGGING SYSTEM (MANUAL MODE)")
    print("=" * 60)

    # Optional clear logs
    choice = input("\nDo you want to clear existing logs? (y/n): ").lower()

    if choice == "y" and os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
        print("✔ logs.json cleared\n")

    while True:
        print("\n1. Add Log")
        print("2. Exit")

        option = input("Enter choice: ")

        if option == "1":
            event_type = input("Enter event type: ")
            description = input("Enter description: ")

            add_log(event_type, description)

        elif option == "2":
            print("\nExiting...")
            break

        else:
            print("❌ Invalid choice")