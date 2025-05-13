# BingleHTTPFileServer

BingleHTTPFileServer is a Python-based secure HTTP server designed for easy file management, sharing, and user administration. It features robust password security using bcrypt, support for multiple root storage directories, and a comprehensive web-based admin panel.

## Features

*   **Secure User Authentication**: Credentials stored with bcrypt hashing.
*   **Role-Based Access Control**: Differentiates between 'admin' and 'user' roles.
*   **Multi-Root Directory Support**:
    *   Configure multiple independent file storage locations.
    *   Admin interface to dynamically add or remove root directories.
    *   Users can select their desired root directory for file operations.
*   **File Management**:
    *   Browse and navigate nested folders.
    *   Upload files to the selected root directory.
    *   Download files.
    *   Search for files within the current directory.
*   **Public Link Sharing**:
    *   Generate secure, time-limited (by token expiration policy) public links for files.
    *   Admin panel to view all active public links.
    *   Admin ability to delete individual public links or clear all existing links.
*   **Comprehensive Admin Panel**:
    *   **Settings**:
        *   Manage root storage directories.
        *   Change the logged-in admin's credentials.
        *   Manage public links (list, delete, clear all).
    *   **User Management**:
        *   List all users.
        *   Create new users with 'admin' or 'user' roles.
        *   Delete existing users (with safeguards for the last admin).
        *   Change passwords for any user.
*   **Modern UI**:
    *   Customizable server logo display.
    *   Favicon support.
    *   Modernized file input/upload interface.
    *   Responsive design elements for better usability.
*   **Range Request Support**: For efficient streaming of media files (e.g., for video players).
*   **Automatic Configuration File Creation**:
    *   `users.json` (for user accounts) is created with a default admin if missing.
    *   `root_dir.json` (for root directories) is created with a default 'uploads' directory if missing.
    *   `public_links.json` (for shared links) is created when the first link is generated or managed.

## Prerequisites

*   Python 3.7+
*   `pip` (Python package installer)

## Installation

1.  **Clone the repository or download the source code.**
    If you have git installed:
    ```bash
    git clone <repository_url>
    cd BingleHTTPFileServer
    ```
    Otherwise, download and extract the project files.

2.  **Install dependencies:**
    Navigate to the project directory in your terminal and run:
    ```bash
    pip install -r requirements.txt
    ```
    This will install `bcrypt` and any other necessary Python packages.

## Configuration Files

The server uses several JSON files for persistent storage, located in the same directory as `binglehttp.py`:

*   **`users.json`**: Stores user account information, including usernames, hashed passwords, salts, and roles.
    *   **Auto-created on first run if missing**, with a default admin user:
        *   Username: `admin`
        *   Password: `Password` (It is **strongly recommended** to change this immediately after first login).
*   **`root_dir.json`**: Stores the list of configured root directories for file storage.
    *   **Auto-created on first run if missing**, with a default configuration:
      ```json
      {
          "root_dirs": ["uploads"]
      }
      ```
    *   The `uploads` directory will also be created in the server's root if it doesn't exist.
    *   You can manage these directories via the Admin Panel -> Settings.
*   **`public_links.json`**: Stores active public links and their corresponding file paths.
    *   **Created when the first public link is generated** or managed (e.g., cleared by an admin). If no links are ever created, this file might not exist initially. It will contain an empty JSON object `{}` if all links are cleared.

## Running the Server

Navigate to the project directory in your terminal and run the server script:

```bash
python binglehttp.py
```

By default, the server will start on `0.0.0.0:6799`. You can access it by opening a web browser and going to `http://localhost:6799` or `http://<your_server_ip>:6799`.

The console will display the configured root directories upon startup.

## First Time Login & Usage

1.  Open your web browser and navigate to the server's address (e.g., `http://localhost:6799`).
2.  You will be presented with a login screen.
3.  **Default Admin Credentials**:
    *   Username: `admin`
    *   Password: `Password`
4.  **Important**: After logging in as admin for the first time, it is highly recommended to change the default admin credentials:
    *   Click the "Admin Menu" button (top right).
    *   Select "Settings".
    *   Under "Change Admin Credentials", enter a new username and a strong new password for the current admin account.

## Admin Panel Overview

Once logged in as an admin, the "Admin Menu" button provides access to:

### 1. Settings

*   **Manage Root Directories**:
    *   View currently configured root directories.
    *   Add new root directories by providing an absolute path. The server will attempt to create the directory if it doesn't exist.
    *   Remove existing root directories (the last one cannot be removed).
*   **Change Admin Credentials**:
    *   Allows the currently logged-in admin to change their own username and password.
*   **Manage Public Links**:
    *   View a table of all currently active public links, including the file path and a clickable (opens in new tab) partial link key.
    *   Delete individual public links using the "Delete" button next to each link (with inline confirmation).
    *   "Clear All Public Links" button (with inline confirmation) to remove all existing public links.

### 2. Manage Users

*   **Create New User**:
    *   Form to create new users with a username, password, and role (`user` or `admin`).
*   **Current Users**:
    *   Lists all registered users with their username and role.
    *   **Change Password**: For each user, an admin can set a new password using an inline form.
    *   **Delete User**: For each user (except the admin's own account), an admin can delete the user account (with inline confirmation). Safeguards prevent deletion of the last admin account.

## User Functionality (for all logged-in users)

*   **View/Manage Files Button**:
    *   Clicking this button initiates the root directory selection process.
    *   If multiple root directories are configured, a modal appears allowing the user to choose which repository they want to work with.
    *   If only one root is configured, it's selected automatically.
*   **File Browser Page**:
    *   Displays files and folders within the selected root directory and current path.
    *   Navigate into folders by clicking their names.
    *   Use the "..(Up)" link to navigate to the parent directory.
    *   Search for files within the currently displayed directory.
    *   **Download**: Download files to your local machine.
    *   **Get Public Link**: Generate a shareable public link for a file. The link is displayed in the file row and can be right-clicked to copy. These links are associated with the user's session token validity and are managed via `public_links.json`.
*   **Upload Files**:
    *   On the main page (after login), users can upload files.
    *   An "Upload to:" dropdown allows selection of the target root directory for the upload. This dropdown is automatically populated with available root directories.
    *   A modern "Browse..." button allows file selection, with the chosen filename displayed next to it.

## Customization

*   **Logo**: Place a `BingleLogo.png` file in the same directory as `binglehttp.py` to display it at the top of the page.
*   **Favicon**: Place a `favicon.ico` file in the same directory as `binglehttp.py` to set the browser tab icon.

## Security Notes

*   Passwords are not stored in plaintext. `bcrypt` is used for hashing and salting.
*   Session tokens are tied to the user's IP address.
*   Session tokens have an expiration time (`TOKEN_EXPIRATION_SECONDS` in `binglehttp.py`). Active file transfers can extend token life.
*   Path traversal attempts in file operations, public links, and root directory paths are checked and blocked.

This README provides a good overview. You can copy and paste this content into your `README.md` file. 