# File Janitor 🧹

A modern, multi-tool graphical application designed to help you analyze, clean, and manage your file storage. Built with Python and `ttkbootstrap`, this suite provides a user-friendly sidebar interface to tackle common storage management tasks.

## Features

*   **Dashboard**: Quick overview of file counts and storage usage for a selected folder.
*   **Duplicate File Finder**: Scans directories to find and manage files with identical content. Features "Smart Select" for easy cleanup.
*   **Large File Finder**: Quickly locates files that exceed a user-specified size.
*   **Old File Finder**: Identifies files that haven't been modified in a long time (e.g., > 6 months).
*   **Temp File Cleaner**: Scans for and removes common temporary and junk files.
*   **File Organizer**: Automatically sorts files into subfolders based on type (Images, Documents, Audio, etc.).
*   **Batch Renamer**: Rename multiple files at once using customizable patterns.
*   **File Type Analyzer**: Provides a summary of disk space usage broken down by file extension.
*   **Empty Folder Cleaner**: Recursively finds and deletes empty subdirectories.
*   **Modern GUI**: A clean, sidebar-based interface with toggleable Light/Dark themes.
*   **Safe & Responsive**: Operations run in a background thread to keep the UI responsive.

## Requirements

*   Python 3.7+
*   ttkbootstrap
    ```bash
    pip install ttkbootstrap
    ```

## How to Use

1.  Clone this repository:
    ```bash
    git clone https://github.com/CrimsonDevil333333/File-Janitor.git
    cd File-Janitor
    ```

2.  Install the required library:
    ```bash
    pip install ttkbootstrap
    ```

3.  Run the application:
    ```bash
    python file_janitor.py
    ```

4.  Use the **Sidebar** to navigate between different tools.
5.  Select a folder and run the desired scan or operation.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.