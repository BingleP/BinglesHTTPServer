import json
import os
import bcrypt # Import bcrypt

# File for storing users
USERS_FILE = "users.json"

# --- Hashing for Default Admin ---
# Generate salt and hash for the default password "Password"
default_password = "Password"
default_salt = bcrypt.gensalt()
default_hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), default_salt).decode('utf-8')
# Store hash and salt as strings

# Default admin user if no file exists - NOW WITH HASHED PASSWORD
DEFAULT_USERS = {
    "Admin": {"hashed_password": default_hashed_password, "salt": default_salt.decode('utf-8'), "role": "admin"}
}

# Global users dictionary
users = {}

def load_users():
    """Load users from the USERS_FILE or use defaults if file doesn't exist"""
    global users
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                users = json.load(f)
                print(f"Successfully loaded users from {USERS_FILE}. {len(users)} users loaded.")
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse {USERS_FILE} due to JSONDecodeError: {e}. Using default users.")
            users = DEFAULT_USERS.copy()
            save_users()  # Create a valid file for next time
        except Exception as e:
            print(f"ERROR: An unexpected error occurred while loading {USERS_FILE}: {e}. Using default users.")
            users = DEFAULT_USERS.copy()
            save_users()  # Create a valid file for next time
    else:
        print(f"{USERS_FILE} not found. Initializing with default users.")
        users = DEFAULT_USERS.copy()
        save_users()  # Create the file

def save_users():
    """Save the current users dictionary to the USERS_FILE"""
    # Ensure users is loaded before saving, just in case
    if not users:
        load_users()
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def get_user(username):
    """Get a user by username, excluding password info."""
    user_data = users.get(username)
    if user_data:
        # Return a copy without sensitive fields
        return {"username": username, "role": user_data.get("role")}
    return None

def get_user_auth_data(username):
    """Internal helper to get auth data (hash, salt) for verification."""
    user_data = users.get(username)
    if user_data and "hashed_password" in user_data and "salt" in user_data:
        return {"hashed_password": user_data["hashed_password"], "salt": user_data["salt"]}
    return None

def add_user(username, password, role="user"):
    """Add a new user with a hashed password and salt."""
    if username in users:
        return False # User already exists

    if not password:
        print(f"ERROR: Attempted to add user '{username}' with empty password.")
        return False # Prevent adding user with empty password

    try:
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        users[username] = {
            "hashed_password": hashed_password.decode('utf-8'), # Store as string
            "salt": salt.decode('utf-8'), # Store as string
            "role": role
        }
        save_users()
        print(f"User '{username}' added successfully.")
        return True
    except Exception as e:
        print(f"ERROR: Failed to hash password for user '{username}': {e}")
        return False

def update_user(username, password=None, role=None):
    """Update an existing user. Hashes password if provided."""
    if username not in users:
        return False # User does not exist

    updated = False
    if password:
        try:
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            users[username]["hashed_password"] = hashed_password.decode('utf-8')
            users[username]["salt"] = salt.decode('utf-8')
            print(f"Password updated for user '{username}'.")
            updated = True
        except Exception as e:
            print(f"ERROR: Failed to hash new password for user '{username}': {e}")
            # Decide if you want to stop the update entirely or just skip password part
            # return False # Option: Fail the whole update
            pass # Option: Continue to update role if provided

    if role:
        if role in ["admin", "user"]: # Basic role validation
             users[username]["role"] = role
             print(f"Role updated for user '{username}' to '{role}'.")
             updated = True
        else:
            print(f"WARN: Invalid role '{role}' provided for user '{username}'. Role not updated.")


    if updated:
        save_users()
    return updated # Return True if any change was made and saved

def delete_user(username):
    """Delete a user"""
    # Optional: Add logic to prevent deleting the last admin user
    if username not in users:
        return False
    
    # Prevent deleting the last admin
    admins = [u for u, data in users.items() if data.get("role") == "admin"]
    if users[username].get("role") == "admin" and len(admins) <= 1:
        print(f"WARN: Cannot delete user '{username}' as they are the last admin.")
        return False

    del users[username]
    save_users()
    print(f"User '{username}' deleted.")
    return True

def verify_password(username, provided_password):
    """Verify a provided password against the stored hash for the user."""
    auth_data = get_user_auth_data(username)
    if not auth_data:
        print(f"Password verification failed for '{username}': User or auth data not found.")
        return False

    stored_hash = auth_data['hashed_password'].encode('utf-8')
    stored_salt = auth_data['salt'].encode('utf-8') # Retrieve salt as bytes

    try:
        # Hash the provided password with the stored salt and compare
        return bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash)
    except ValueError as e:
         # This can happen if the stored hash is malformed, e.g., not a valid bcrypt hash
         print(f"ERROR during password check for user '{username}': Invalid hash format? {e}")
         return False
    except Exception as e:
         print(f"ERROR during password check for user '{username}': {e}")
         return False

def list_users():
    """Return a list of user objects, each containing username and role."""
    if not users:
        load_users()
    # Ensure sensitive data is not included
    return [{"username": uname, "role": uinfo.get("role", "user")}
            for uname, uinfo in users.items()]

# Initialize users
load_users()
