#!/usr/bin/env python3
"""
Test File: vulnerable.py
Purpose: Intentionally vulnerable Python code for testing the Cosine SAST engine.
Contains real security flaws along with safe reference patterns to test zero-false-positive filtering.
"""

import os
import sys
import pickle
import base64
import sqlite3
import subprocess

# Vulnerability 1: Hardcoded Secret / API Token (CWE-798)
API_SECRET_TOKEN = "AKIAIOSFODNN7EXAMPLE_PYTHON_SECRET_KEY_1234567890"

# Vulnerability 2: Insecure Shell / Command Injection (CWE-78)
# Concatenating unvalidated user input into shell=True subprocess execution
def ping_server(host: str):
    cmd = f"ping -c 1 {host}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# Safe Reference: Safe command execution (should NOT be flagged as vulnerable)
def ping_server_safe(host: str):
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)

# Vulnerability 3: Insecure Deserialization via pickle (CWE-502)
# Untrusted user data passed to pickle.loads can lead to arbitrary code execution
def load_session(serialized_data: str):
    raw_bytes = base64.b64decode(serialized_data)
    return pickle.loads(raw_bytes)

# Vulnerability 4: Path Traversal & Arbitrary File Write (CWE-22)
# Unsanitized filename allows directory traversal (e.g., ../../etc/cron.d/malicious)
def save_uploaded_file(filename: str, content: str):
    target_path = f"/var/data/uploads/{filename}"
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(content)

# Vulnerability 5: SQL Injection (CWE-89)
# Direct string formatting into SQL statement allows authentication bypass or data leakage
def find_user_by_name(cursor: sqlite3.Cursor, username: str):
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    return cursor.execute(query).fetchall()

# Safe Reference: Parameterized SQL Query (should NOT be flagged as vulnerable)
def find_user_safe(cursor: sqlite3.Cursor, username: str):
    query = "SELECT id, username, role FROM users WHERE username = ?"
    return cursor.execute(query, (username,)).fetchall()

def main():
    if len(sys.argv) < 2:
        print("Usage: vulnerable.py <action> [args...]")
        sys.exit(1)

    action = sys.argv[1]

    if action == "ping" and len(sys.argv) > 2:
        res = ping_server(sys.argv[2])
        print(res.stdout)
    elif action == "session" and len(sys.argv) > 2:
        data = load_session(sys.argv[2])
        print("Loaded session:", data)
    elif action == "upload" and len(sys.argv) > 3:
        save_uploaded_file(sys.argv[2], sys.argv[3])
    elif action == "user" and len(sys.argv) > 2:
        conn = sqlite3.connect(":memory:")
        cur = conn.cursor()
        users = find_user_by_name(cur, sys.argv[2])
        print(users)

if __name__ == "__main__":
    main()
