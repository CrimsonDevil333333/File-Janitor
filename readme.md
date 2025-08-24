# File Janitor 🧹

A modern, multi-tool graphical application designed to help you analyze, clean, and manage your file storage. Built with Python and `ttkbootstrap`, this suite provides a user-friendly interface to tackle common storage management tasks.

*A screenshot of the File Janitor application in action.*

## Features

* **Duplicate File Finder**: Scans directories to find and manage files with identical content using a two-phase check (size then hash). Features multi-select and a "Smart Select" option for easy cleanup.
* **Large File Finder**: Quickly locates files that exceed a user-specified size, helping you identify the biggest storage hogs.
* **File Type Analyzer**: Provides a summary of disk space usage broken down by file extension, showing what's taking up your space.
* **Empty Folder Cleaner**: Recursively finds and deletes empty subdirectories to reduce clutter.
* **Modern GUI**: A clean, tabbed interface with toggleable Light/Dark themes.
* **Safe & Responsive**: Operations run in a background thread to keep the UI responsive, with a cancel button available.
* **Export & Save**: Export scan results to a `.csv` file and have your window settings saved for the next session.

## Requirements

* Python 3.7+
* ttkbootstrap
    ```bash
    pip install ttkbootstrap
    ```

## How to Use

1.  Clone this repository:
    ```bash
    git clone [https://github.com/CrimsonDevil333333/File-Janitor.git](https://github.com/CrimsonDevil333333/File-Janitor.git)
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
    *(Note: Rename `file_janitor.py` to the actual name of your Python script file.)*

4.  In the application window, select a tool from the tabs, click the primary button to choose a folder, and let the scan run.
5.  Review the results and use the provided options to manage your files.


## License

This project is licensed under the MIT License. See the `LICENSE` file for details.