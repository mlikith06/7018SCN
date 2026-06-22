import hashlib
import os
import re
import time
import json


# ---------------- PASSWORD VALIDATION ----------------
def check_password_complexity(password):
    pattern = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*]).{12,}$'

    if not re.match(pattern, password):
        print("Password must be at least 12 characters, include a number and special character.")
        return False

    return True


# ---------------- SALT GENERATION ----------------
def generate_salt():
    return os.urandom(16)


# ---------------- HASHING ----------------
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000
    ).hex()


# ---------------- LOAD USERS ----------------
def load_users():
    try:
        with open("users.json", "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ---------------- SAVE USERS ----------------
def save_users(users):
    try:
        with open("users.json", "w") as file:
            json.dump(users, file, indent=4)
    except Exception as e:
        print("Error saving users:", e)


# ---------------- REGISTER ----------------
def register():
    try:
        users = load_users()

        username = input("Enter username: ").strip()

        if not username:
            print("Username cannot be empty.")
            return

        if username in users:
            print("Username already exists.")
            return

        # ✅ PASSWORD RETRY LOOP (IMPORTANT FIX)
        while True:
            password = input("Enter password: ").strip()

            if check_password_complexity(password):
                break
            else:
                print("Please try again...\n")

        salt = generate_salt()
        hashed_password = hash_password(password, salt)

        users[username] = {
            "salt": salt.hex(),
            "password_hash": hashed_password
        }

        save_users(users)

        print("User registered successfully!")

    except Exception as e:
        print("Error during registration:", e)


# ---------------- LOGIN ----------------
def login():
    try:
        users = load_users()

        if not users:
            print("No registered users found.")
            return

        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()

        if username not in users:
            print("User not found.")
            time.sleep(2)
            return

        user = users[username]
        salt = bytes.fromhex(user["salt"])

        hashed_password = hash_password(password, salt)

        if hashed_password == user["password_hash"]:
            print("Login successful!")
        else:
            print("Login failed!")
            print("Waiting 2 seconds to prevent brute-force attacks...")
            time.sleep(2)

    except Exception as e:
        print("Error during login:", e)


# ---------------- MAIN MENU ----------------
while True:

    print("\nSecure Authentication System")
    print("1. Register")
    print("2. Login")
    print("3. Exit")

    choice = input("Select option: ").strip()

    if choice == "1":
        register()

    elif choice == "2":
        login()

    elif choice == "3":
        print("Exiting program.")
        break

    else:
        print("Invalid option.")