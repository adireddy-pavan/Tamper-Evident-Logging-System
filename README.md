# 🔐 Tamper-Evident Logging System

## 📌 Overview

This project implements a **Tamper-Evident Logging System** that ensures the integrity and security of log data using cryptographic techniques.

Each log entry is linked to the previous one using a **SHA-256 hash**, forming a secure chain. Any modification, deletion, or reordering of logs will break the chain and can be detected during verification.

---

## ⚙️ Features

* Add logs manually
* Secure hash chaining between logs
* Detect:

  * ✔ Data modification
  * ✔ Log deletion
  * ✔ Log reordering
* Clear and structured log display
* Works using JSON-based storage

---

## 🏗️ System Design

Each log entry contains:

* Sequence ID
* Timestamp
* Event Type
* Description
* Metadata (optional)
* Previous Hash
* Current Hash

### 🔗 Hash Chain Mechanism

Each log stores the hash of the previous log:

```
Current Hash = SHA256(sequence_id + timestamp + event_type + description + metadata + previous_hash)
```

This ensures that any change in one log affects all subsequent logs.

---

## 📂 Project Files

* `add_logs.py` → Used to add new log entries
* `verify.py` → Used to verify log integrity
* `logs.json` → Stores all log entries

---

## 🚀 How to Run

### Step 1: Add Logs

Run the following command:

```
python add_logs.py
```

* Enter event type and description manually
* Logs will be stored securely in `logs.json`

---

### Step 2: Verify Logs

Run:

```
python verify.py
```

* Checks:

  * Hash integrity
  * Chain linkage
  * Sequence correctness

---

## 🧪 How to Test Tampering

1. Open `logs.json`
2. Perform any of the following:

   * Modify description
   * Delete a log
   * Change order of logs
3. Run:

```
python verify.py
```

### Expected Output:

```
✘ CONTENT MODIFIED
✘ CHAIN BROKEN
✘ SEQUENCE GAP
```

---

## 🎯 Applications

* Cybersecurity logging systems
* Banking transaction logs
* Audit trails
* Digital forensics

---

## 📊 Conclusion

This system ensures that logs cannot be altered without detection.
It demonstrates how **cryptographic hashing** can be used to maintain data integrity in real-world applications.

---

## 👨‍💻 Author

Pavan Adireddy
