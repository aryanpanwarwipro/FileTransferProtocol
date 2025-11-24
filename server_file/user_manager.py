#!/usr/bin/env python3
import json, os, sys
from securehash import hash_password
 
FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")
 
def load_users():
    if not os.path.exists(FILE):
        return []
    with open(FILE, "r") as f:
        return json.load(f)
 
def save_users(users):
    with open(FILE, "w") as f:
        json.dump(users, f, indent=4)
 
def add_user(username, password, role):
    users = load_users()
    if any(u["username"] == username for u in users):
        print("❌ User already exists")
        return
 
    hashed = hash_password(password)
 
    users.append({
        "username": username,
        "password": hashed,
        "role": role,
        "locked": False
    })
    save_users(users)
    print(f"✅ User '{username}' added successfully.")
 
def reset_password(username, newpass):
    users = load_users()
    for u in users:
        if u["username"] == username:
            u["password"] = hash_password(newpass)
            save_users(users)
            print("🔁 Password reset successful.")
            return
    print("❌ User not found.")
 
def list_users():
    users = load_users()
    print("\n=== Registered Users ===")
    for u in users:
        state = "LOCKED" if u.get("locked") else "ACTIVE"
        print(f"- {u['username']} ({u['role']}, {state})")
    print("========================\n")
 
def help_menu():
    print(
        """
Usage:
    python3 user_manager.py add <username> <password> <role>
    python3 user_manager.py reset <username> <newpassword>
    python3 user_manager.py list
"""
    )
 
if __name__ == "__main__":
    if len(sys.argv) < 2:
        help_menu()
        sys.exit(0)
 
    cmd = sys.argv[1].lower()
 
    if cmd == "add" and len(sys.argv) == 5:
        add_user(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "reset" and len(sys.argv) == 4:
        reset_password(sys.argv[2], sys.argv[3])
    elif cmd == "list":
        list_users()
    else:
        help_menu()