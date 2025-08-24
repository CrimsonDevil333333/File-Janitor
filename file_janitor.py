import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
import threading
import queue
from pathlib import Path
import os
import hashlib
import json
from datetime import datetime
from collections import defaultdict
import csv

# --- Constants ---
SETTINGS_FILE = "file_janitor_settings.json"


# --- Backend Functions ---
# These must be defined before the class that uses them.

def find_duplicates_logic(progress_queue, cancel_event, folder_path):
    """Finds duplicate files based on size and then hash."""
    files = [p for p in Path(folder_path).rglob("*") if p.is_file()]
    total_files = len(files)

    files_by_size = defaultdict(list)
    for i, path in enumerate(files):
        if cancel_event.is_set():
            progress_queue.put({"type": "done", "message": "Cancelled"})
            return
        progress_queue.put({"type": "progress", "value": (i/total_files)*30, "status": f"Phase 1/2: Sizing files..."})
        try:
            size = path.stat().st_size
            if size > 4096: # Ignore very small files
                files_by_size[size].append(path)
        except FileNotFoundError:
            continue

    hashes_by_size = defaultdict(list)
    potential_dupes = [p for paths in files_by_size.values() if len(paths) > 1 for p in paths]
    total_potential_dupes = len(potential_dupes) if len(potential_dupes) > 0 else 1

    for i, path in enumerate(potential_dupes):
        if cancel_event.is_set():
            progress_queue.put({"type": "done", "message": "Cancelled"})
            return
        progress_queue.put({"type": "progress", "value": 30 + (i/total_potential_dupes)*70, "status": f"Phase 2/2: Hashing {path.name}"})
        try:
            file_hash = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            hashes_by_size[file_hash.hexdigest()].append(path)
        except Exception:
            continue

    group_id_counter = 0
    for file_hash, paths in hashes_by_size.items():
        if len(paths) > 1:
            group_id_counter += 1
            for path in sorted(paths):  # Sort paths for consistent ordering
                try:
                    stat = path.stat()
                    size_kb = stat.st_size / 1024
                    mod_time = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
                    data = (path.name, str(path.parent), f"{size_kb:.2f}", mod_time)
                    progress_queue.put({"type": "dup_result", "group_id": group_id_counter, "data": data})
                except FileNotFoundError:
                    continue

    progress_queue.put({"type": "done", "message": "Duplicate scan complete!"})


def find_duplicates(progress_queue, cancel_event, folder_path):
    """Wrapper for the duplicate finding logic."""
    find_duplicates_logic(progress_queue, cancel_event, folder_path)


def find_large_files(progress_queue, cancel_event, folder_path, min_size_mb):
    """Finds files larger than a specified size."""
    files = list(Path(folder_path).rglob("*"))
    total_files = len(files) if files else 1
    min_size_bytes = min_size_mb * 1024 * 1024
    for i, path in enumerate(files):
        if cancel_event.is_set():
            progress_queue.put({"type": "done", "message": "Cancelled"})
            return
        if not path.is_file():
            continue
        progress_queue.put({"type": "progress", "value": (i/total_files)*100, "status": f"Scanning: {path.name}"})
        try:
            size = path.stat().st_size
            if size >= min_size_bytes:
                size_mb = size / (1024 * 1024)
                progress_queue.put({"type": "large_file_result", "data": (path.name, str(path.parent), f"{size_mb:.2f}")})
        except FileNotFoundError:
            continue
    progress_queue.put({"type": "done", "message": "Large file scan complete!"})


def analyze_file_types(progress_queue, cancel_event, folder_path):
    """Analyzes disk usage by file extension."""
    files = list(Path(folder_path).rglob("*"))
    total_files = len(files) if files else 1
    type_summary = defaultdict(lambda: {'count': 0, 'size': 0})
    for i, path in enumerate(files):
        if cancel_event.is_set():
            progress_queue.put({"type": "done", "message": "Cancelled"})
            return
        if not path.is_file():
            continue
        progress_queue.put({"type": "progress", "value": (i/total_files)*100, "status": f"Analyzing: {path.name}"})
        ext = path.suffix.lower() if path.suffix else ".no_extension"
        try:
            size = path.stat().st_size
            type_summary[ext]['count'] += 1
            type_summary[ext]['size'] += size
        except FileNotFoundError:
            continue
    for ext, data in type_summary.items():
        size_mb = data['size'] / (1024 * 1024)
        progress_queue.put({"type": "analyzer_result", "data": (ext, data['count'], f"{size_mb:.2f}")})
    progress_queue.put({"type": "done", "message": "Analysis complete!"})


def clean_empty_folders(progress_queue, cancel_event, folder_path):
    """Finds and removes empty subdirectories."""
    progress_queue.put({"type": "progress", "value": 10, "status": "Locating empty folders..."})
    empty_folders_found = []
    for dirpath, dirnames, filenames in os.walk(folder_path, topdown=False):
        if cancel_event.is_set():
            progress_queue.put({"type": "done", "message": "Cancelled"})
            return
        if not dirnames and not filenames:
            empty_folders_found.append(dirpath)
            progress_queue.put({"type": "cleaner_log", "data": f"Found empty folder: {dirpath}"})

    progress_queue.put({"type": "progress", "value": 50, "status": "Removing folders..."})
    if not empty_folders_found:
        progress_queue.put({"type": "cleaner_log", "data": "No empty folders found to remove."})
    else:
        for folder in empty_folders_found:
            if cancel_event.is_set():
                progress_queue.put({"type": "done", "message": "Cancelled"})
                return
            try:
                os.rmdir(folder)
                progress_queue.put({"type": "cleaner_log", "data": f"Removed: {folder}"})
            except OSError as e:
                progress_queue.put({"type": "cleaner_log", "data": f"Failed to remove {folder}: {e}"})

    progress_queue.put({"type": "done", "message": "Cleaning complete!"})


# --- Main Application Class ---

class FileJanitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Janitor 🧹")
        self.root.geometry("1000x750")

        self.progress_queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.is_running = False
        self.run_buttons = []
        self.last_folder = os.path.expanduser("~")

        self.setup_ui()
        self.load_settings()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.after(100, self.process_queue)

    def setup_ui(self):
        """Creates the main UI structure and widgets."""
        main_frame = ttk.Frame(self.root, padding=(20, 10))
        main_frame.pack(fill=BOTH, expand=YES)

        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=X, padx=10, pady=(5, 10))

        title_label = ttk.Label(header_frame, text="File Janitor", font=("Segoe UI", 16, "bold"))
        title_label.pack(side=LEFT)

        self.theme_var = tk.StringVar(value="dark")
        theme_toggle_button = ttk.Checkbutton(
            header_frame,
            text="Light/Dark",
            variable=self.theme_var,
            command=self.toggle_theme,
            onvalue="dark",
            offvalue="light",
            bootstyle="light-round-toggle"
        )
        theme_toggle_button.pack(side=RIGHT)

        tabControl = ttk.Notebook(main_frame)
        tabControl.pack(expand=YES, fill=BOTH, padx=10, pady=5)

        tabs = {
            "Duplicate Finder": self.setup_duplicate_finder_tab,
            "Large File Finder": self.setup_large_file_finder_tab,
            "File Type Analyzer": self.setup_analyzer_tab,
            "Empty Folder Cleaner": self.setup_empty_folder_cleaner_tab
        }

        for name, setup_func in tabs.items():
            tab = ttk.Frame(tabControl, padding=10)
            tabControl.add(tab, text=name)
            setup_func(tab)

        status_frame = ttk.Frame(main_frame, padding=(10, 5))
        status_frame.pack(fill=X)
        self.status_label = ttk.Label(status_frame, text="Ready")
        self.status_label.pack(side=LEFT, fill=X, expand=YES)
        self.cancel_button = ttk.Button(
            status_frame,
            text="Cancel",
            command=self.cancel_operation,
            state=DISABLED,
            bootstyle="danger-outline"
        )
        self.cancel_button.pack(side=RIGHT)
        self.progress_bar = ttk.Progressbar(main_frame, bootstyle="info-striped")
        self.progress_bar.pack(fill=X, padx=10, pady=(0, 10))

    def setup_duplicate_finder_tab(self, parent_tab):
        paned_window = ttk.PanedWindow(parent_tab, orient=HORIZONTAL)
        paned_window.pack(fill=BOTH, expand=YES)

        left_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(left_frame, weight=3)
        right_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(right_frame, weight=1)

        results_frame = ttk.LabelFrame(left_frame, text="Found Duplicates (Grouped)", padding=10)
        results_frame.pack(fill=BOTH, expand=YES)
        self.dup_tree = self.create_results_tree(results_frame, ("File Name", "Path", "Size (KB)", "Modified Date"))
        
        # Pass this tab's specific preview labels to the event handler
        self.dup_preview_labels = self.create_preview_pane(right_frame, "File Preview")
        self.dup_tree.bind('<<TreeviewSelect>>', lambda e: self.on_file_select(e, self.dup_tree, 1, self.dup_preview_labels))
        
        btn_frame = self.create_button_bar(
            left_frame, 
            run_cmd=self.start_duplicate_scan, 
            del_cmd=lambda: self.delete_selected_from_tree(self.dup_tree, 1), 
            export_cmd=lambda: self.export_treeview_to_csv(self.dup_tree),
            smart_select_cmd=self.smart_select_duplicates
        )
        btn_frame['run_btn'].config(text="Find Duplicates")


    def setup_large_file_finder_tab(self, parent_tab):
        paned_window = ttk.PanedWindow(parent_tab, orient=HORIZONTAL)
        paned_window.pack(fill=BOTH, expand=YES)
        left_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(left_frame, weight=3)
        right_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(right_frame, weight=1)

        options_frame = ttk.LabelFrame(left_frame, text="Options", padding=10)
        options_frame.pack(fill=X, pady=(0, 10))
        ttk.Label(options_frame, text="Find files larger than (MB):").pack(side=LEFT, padx=5)
        self.min_size_var = tk.StringVar(value="100")
        ttk.Entry(options_frame, textvariable=self.min_size_var, width=10).pack(side=LEFT)

        results_frame = ttk.LabelFrame(left_frame, text="Large Files Found", padding=10)
        results_frame.pack(fill=BOTH, expand=YES)
        self.large_files_tree = self.create_results_tree(results_frame, ("File Name", "Path", "Size (MB)"))
        
        # Pass this tab's specific preview labels to the event handler
        self.large_file_preview_labels = self.create_preview_pane(right_frame, "File Preview")
        self.large_files_tree.bind('<<TreeviewSelect>>', lambda e: self.on_file_select(e, self.large_files_tree, 1, self.large_file_preview_labels))

        btn_frame = self.create_button_bar(left_frame, self.start_large_file_scan, lambda: self.delete_selected_from_tree(self.large_files_tree, 1), lambda: self.export_treeview_to_csv(self.large_files_tree))
        btn_frame['run_btn'].config(text="Find Large Files")

    def setup_analyzer_tab(self, parent_tab):
        results_frame = ttk.LabelFrame(parent_tab, text="Disk Usage by File Type", padding=10)
        results_frame.pack(fill=BOTH, expand=YES, pady=5)
        self.analyzer_tree = self.create_results_tree(results_frame, ("Extension", "File Count", "Total Size (MB)"))

        button_frame = ttk.Frame(parent_tab)
        button_frame.pack(fill=X, pady=5)
        btn = ttk.Button(button_frame, text="Choose Folder & Analyze", command=self.start_analyzer_scan, bootstyle="primary")
        btn.pack(side=LEFT, expand=YES, fill=X, padx=(0, 5))
        self.run_buttons.append(btn)
        ttk.Button(button_frame, text="Export to CSV", command=lambda: self.export_treeview_to_csv(self.analyzer_tree), bootstyle="secondary-outline").pack(side=LEFT, expand=YES, fill=X)

    def setup_empty_folder_cleaner_tab(self, parent_tab):
        log_frame = ttk.LabelFrame(parent_tab, text="Log", padding=10)
        log_frame.pack(fill=BOTH, expand=YES, pady=5)
        self.cleaner_log = ScrolledText(log_frame, wrap=WORD, height=10, autohide=True)
        self.cleaner_log.pack(fill=BOTH, expand=YES)

        btn = ttk.Button(parent_tab, text="Choose Folder & Clean Empties", command=self.start_cleanup, bootstyle="primary")
        btn.pack(fill=X, pady=5)
        self.run_buttons.append(btn)

    def create_results_tree(self, parent, columns):
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=BOTH, expand=YES)
        # NEW: Added selectmode=EXTENDED to make multi-select explicit
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings", bootstyle="info", selectmode=EXTENDED)
        for col in columns:
            tree.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(tree, _col, False))
            tree.column(col, width=120, anchor=W)

        scrollbar = ttk.Scrollbar(tree_frame, orient=VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=LEFT, fill=BOTH, expand=YES)
        scrollbar.pack(side=RIGHT, fill=Y)
        return tree

    def create_button_bar(self, parent, run_cmd, del_cmd, export_cmd, smart_select_cmd=None):
        frame = ttk.Frame(parent)
        frame.pack(fill=X, pady=(10, 0))

        run_btn = ttk.Button(frame, command=run_cmd, bootstyle="primary")
        run_btn.pack(side=LEFT, expand=YES, fill=X, padx=(0, 5))
        self.run_buttons.append(run_btn)
        
        # NEW: Conditionally add the Smart Select button
        if smart_select_cmd:
            smart_btn = ttk.Button(frame, text="Smart Select", command=smart_select_cmd, bootstyle="success-outline")
            smart_btn.pack(side=LEFT, expand=YES, fill=X, padx=5)

        del_btn = ttk.Button(frame, text="Delete Selected", command=del_cmd, bootstyle="danger-outline")
        del_btn.pack(side=LEFT, expand=YES, fill=X, padx=5)

        export_btn = ttk.Button(frame, text="Export to CSV", command=export_cmd, bootstyle="secondary-outline")
        export_btn.pack(side=LEFT, expand=YES, fill=X, padx=(5, 0))
        return {'run_btn': run_btn, 'del_btn': del_btn, 'export_btn': export_btn}

    def create_preview_pane(self, parent, title):
        pane = ttk.LabelFrame(parent, text=title, padding=10)
        pane.pack(fill=BOTH, expand=YES)
        # FIX: Use a local dictionary instead of a shared self.preview_labels
        preview_labels = {}
        fields = ["Name:", "Path:", "Size:", "Created:", "Modified:"]
        for i, field in enumerate(fields):
            ttk.Label(pane, text=field, font=('Segoe UI', 9, 'bold')).grid(row=i, column=0, sticky="ne", padx=5, pady=2)
            preview_labels[field] = ttk.Label(pane, text="", wraplength=200, anchor=W)
            preview_labels[field].grid(row=i, column=1, sticky="nw", padx=5, pady=2)
        pane.grid_columnconfigure(1, weight=1)
        # FIX: Return the dictionary of labels for this specific pane
        return preview_labels

    # FIX: Modified to accept the correct preview_labels dictionary
    def on_file_select(self, event, tree, path_col_index, preview_labels):
        selection = tree.selection()
        if not selection:
            self.clear_preview_pane(preview_labels)
            return
        item_id = selection[0]
        if not tree.parent(item_id): # Ignore selection of parent group nodes
            self.clear_preview_pane(preview_labels)
            return
        values = tree.item(item_id, "values")
        if not values:
            return
        try:
            file_path_str = os.path.join(values[path_col_index], values[0])
            file_path = Path(file_path_str)
            if not file_path.exists():
                self.clear_preview_pane(preview_labels)
                preview_labels["Name:"].config(text="File not found.")
                return
            stat = file_path.stat()
            size_kb = stat.st_size / 1024
            preview_labels["Name:"].config(text=file_path.name)
            preview_labels["Path:"].config(text=str(file_path.parent))
            preview_labels["Size:"].config(text=f"{size_kb:.2f} KB ({stat.st_size:,} bytes)")
            preview_labels["Created:"].config(text=datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'))
            preview_labels["Modified:"].config(text=datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'))
        except (IndexError, FileNotFoundError):
            self.clear_preview_pane(preview_labels)

    # FIX: Modified to accept the correct preview_labels dictionary
    def clear_preview_pane(self, preview_labels):
        for label in preview_labels.values():
            label.config(text="")

    def export_treeview_to_csv(self, tree):
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save results as CSV")
        if not filename:
            return
        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(tree["columns"])
                for item_id in tree.get_children():
                    parent_text = tree.item(item_id, 'text')
                    if parent_text: # For duplicate finder grouped view
                        writer.writerow([f"--- {parent_text} ---"])
                        for child_id in tree.get_children(item_id):
                            writer.writerow(tree.item(child_id, "values"))
                    else: # For flat views
                        writer.writerow(tree.item(item_id, "values"))

            messagebox.showinfo("Success", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {e}")

    def delete_selected_from_tree(self, tree, path_col_index):
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showinfo("Information", "No files selected to delete.")
            return
        files_to_delete = []
        for item_id in selected_items:
            # Ignore parent items (groups)
            if not tree.parent(item_id):
                continue
            values = tree.item(item_id, "values")
            try:
                full_path = os.path.join(values[path_col_index], values[0])
                if os.path.exists(full_path):
                    files_to_delete.append(full_path)
            except IndexError:
                continue
        if not files_to_delete:
            return
        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to permanently delete {len(files_to_delete)} selected file(s)?\nThis action cannot be undone.", parent=self.root):
            deleted_count = 0
            for path in files_to_delete:
                try:
                    os.remove(path)
                    deleted_count += 1
                except Exception as e:
                    self.status_label.config(text=f"Error deleting {path}: {e}")
            messagebox.showinfo("Deletion Complete", f"Successfully deleted {deleted_count} file(s).")
            # A simple way to update view is just to remove from tree.
            # A full rescan would be more accurate but slower.
            for item_id in selected_items:
                if tree.exists(item_id):
                    tree.delete(item_id)
            self.status_label.config(text="Deletion complete.")

    def on_closing(self):
        self.save_settings()
        self.root.destroy()

    def save_settings(self):
        settings = {
            "geometry": self.root.winfo_geometry(),
            "theme": self.theme_var.get(),
            "last_folder": self.last_folder,
            "min_size_mb": self.min_size_var.get()
        }
        try:
            with open(SETTINGS_FILE, "w") as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            print(f"Error saving settings: {e}")

    def load_settings(self):
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, "r") as f:
                    settings = json.load(f)

                self.root.geometry(settings.get("geometry", "1000x750"))
                theme = settings.get("theme", "dark")
                self.theme_var.set(theme)
                self.toggle_theme()
                self.last_folder = settings.get("last_folder", os.path.expanduser("~"))
                self.min_size_var.set(settings.get("min_size_mb", "100"))
        except Exception as e:
            print(f"Error loading settings: {e}")
            self.last_folder = os.path.expanduser("~")

    def toggle_theme(self):
        theme_name = "superhero" if self.theme_var.get() == "dark" else "litera"
        self.root.style.theme_use(theme_name)

    def start_task(self, task_func, *args):
        if self.is_running:
            messagebox.showwarning("Busy", "An operation is already in progress.")
            return

        folder = filedialog.askdirectory(initialdir=self.last_folder, title="Select a folder to process")
        if not folder:
            return
        self.last_folder = folder

        self.toggle_controls(is_running=True)
        if task_func == find_duplicates:
            self.dup_tree.delete(*self.dup_tree.get_children())
        if task_func == find_large_files:
            self.large_files_tree.delete(*self.large_files_tree.get_children())
        if task_func == analyze_file_types:
            self.analyzer_tree.delete(*self.analyzer_tree.get_children())
        if task_func == clean_empty_folders:
            self.cleaner_log.delete('1.0', tk.END)

        thread = threading.Thread(target=task_func, args=(self.progress_queue, self.cancel_event, folder, *args), daemon=True)
        thread.start()

    def start_duplicate_scan(self):
        self.start_task(find_duplicates)

    def start_large_file_scan(self):
        try:
            min_size = int(self.min_size_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Minimum size must be a number.")
            return
        self.start_task(find_large_files, min_size)

    def start_analyzer_scan(self):
        self.start_task(analyze_file_types)

    def start_cleanup(self):
        self.start_task(clean_empty_folders)
    
    # NEW: Smart selection logic
    def smart_select_duplicates(self):
        """Selects all but the first file in each duplicate group."""
        if self.is_running: return
        
        # Clear previous selection
        current_selection = self.dup_tree.selection()
        if current_selection:
            self.dup_tree.selection_remove(current_selection)

        items_to_select = []
        # Iterate over parent groups
        for group_id in self.dup_tree.get_children():
            children = self.dup_tree.get_children(group_id)
            if len(children) > 1:
                # Add all children except the first one to the selection list
                items_to_select.extend(children[1:])
        
        if items_to_select:
            self.dup_tree.selection_set(items_to_select)
            self.status_label.config(text=f"Smart-selected {len(items_to_select)} files for deletion.")
        else:
            self.status_label.config(text="No duplicates found to smart-select.")


    def cancel_operation(self):
        if self.is_running:
            self.cancel_event.set()
            self.status_label.config(text="Cancelling...")

    def toggle_controls(self, is_running):
        self.is_running = is_running
        state = DISABLED if is_running else NORMAL
        for btn in self.run_buttons:
            btn.config(state=state)
        self.cancel_button.config(state=NORMAL if is_running else DISABLED)
        if not is_running:
            self.cancel_event.clear()
            self.progress_bar.stop()

    def process_queue(self):
        try:
            message = self.progress_queue.get_nowait()
            msg_type = message.get("type")

            if msg_type == "progress":
                self.progress_bar.start()
                self.progress_bar["value"] = message["value"]
                self.status_label.config(text=message["status"])
            elif msg_type == "dup_result":
                parent_id = f"group_{message['group_id']}"
                if not self.dup_tree.exists(parent_id):
                    self.dup_tree.insert("", END, iid=parent_id, text=f"Duplicate Set {message['group_id']}", open=True)
                self.dup_tree.insert(parent_id, END, values=message["data"])
            elif msg_type == "large_file_result":
                self.large_files_tree.insert("", END, values=message["data"])
            elif msg_type == "analyzer_result":
                self.analyzer_tree.insert("", END, values=message["data"])
            elif msg_type == "cleaner_log":
                self.cleaner_log.insert(END, message["data"] + "\n")
                self.cleaner_log.see(END)
            elif msg_type == "done":
                self.progress_bar.stop()
                self.progress_bar["value"] = 0
                self.status_label.config(text="Ready")
                self.toggle_controls(is_running=False)
                messagebox.showinfo("Done", message["message"])
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)

    def treeview_sort_column(self, tv, col, reverse):
        try:
            data_list = [(float(tv.set(k, col)), k) for k in tv.get_children('')]
        except (ValueError, TypeError):
            data_list = [(tv.set(k, col), k) for k in tv.get_children('')]

        data_list.sort(key=lambda item: item[0], reverse=reverse)

        for index, (val, k) in enumerate(data_list):
            tv.move(k, '', index)

        tv.heading(col, command=lambda: self.treeview_sort_column(tv, col, not reverse))


# --- Main Entry Point ---
if __name__ == "__main__":
    root = ttk.Window(themename="superhero")
    app = FileJanitorApp(root)
    root.mainloop()