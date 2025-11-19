import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
import threading
import queue
from pathlib import Path
import os
from datetime import datetime
import csv

import utils
import logic

class FileJanitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Janitor 🧹")
        self.root.geometry("1100x750")

        self.progress_queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.is_running = False
        self.run_buttons = []
        self.last_folder = utils.load_settings().get("last_folder", os.path.expanduser("~"))

        self.setup_ui()
        self.load_settings()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.after(100, self.process_queue)

    def setup_ui(self):
        """Creates the main UI structure with Sidebar."""
        # Main container
        container = ttk.Frame(self.root)
        container.pack(fill=BOTH, expand=YES)

        # Sidebar
        sidebar = ttk.Frame(container, padding=10, bootstyle="secondary")
        sidebar.pack(side=LEFT, fill=Y)
        
        # Content Area
        self.content_area = ttk.Frame(container, padding=20)
        self.content_area.pack(side=RIGHT, fill=BOTH, expand=YES)

        # Sidebar Title
        ttk.Label(sidebar, text="File Janitor", font=("Segoe UI", 16, "bold"), bootstyle="inverse-secondary").pack(pady=(10, 20))

        # Navigation Buttons
        self.nav_buttons = {}
        menu_items = [
            ("Dashboard", "Dashboard", self.show_dashboard),
            ("Duplicate Finder", "Duplicates", self.show_duplicate_finder),
            ("Large File Finder", "Large Files", self.show_large_file_finder),
            ("Old File Finder", "Old Files", self.show_old_file_finder),
            ("Temp File Cleaner", "Temp Files", self.show_temp_file_cleaner),
            ("File Organizer", "Organizer", self.show_organizer),
            ("Batch Renamer", "Renamer", self.show_renamer),
            ("File Type Analyzer", "Analyzer", self.show_analyzer),
            ("Empty Folder Cleaner", "Empty Folders", self.show_empty_folder_cleaner),
        ]

        for text, name, command in menu_items:
            btn = ttk.Button(
                sidebar, 
                text=text, 
                command=lambda c=command, n=name: self.navigate(c, n), 
                bootstyle="secondary", 
                width=20
            )
            btn.pack(pady=2, fill=X)
            self.nav_buttons[name] = btn

        # Theme Toggle at bottom of sidebar - REMOVED
        # self.theme_var = tk.StringVar(value="dark")
        # ... (removed code)

        # Content Area Header (Title + Theme Toggle)
        header_frame = ttk.Frame(self.content_area)
        header_frame.pack(fill=X, pady=(0, 20))

        # Dynamic Title Label (updates based on view)
        self.header_title = ttk.Label(header_frame, text="Dashboard", font=("Segoe UI", 24, "bold"))
        self.header_title.pack(side=LEFT, anchor=W)

        # Theme Toggle Button (Top Right)
        self.theme_var = tk.StringVar(value="dark")
        self.theme_btn = ttk.Checkbutton(
            header_frame,
            text="Dark Mode",
            variable=self.theme_var,
            command=self.toggle_theme,
            onvalue="dark",
            offvalue="light",
            bootstyle="round-toggle"
        )
        self.theme_btn.pack(side=RIGHT, anchor=E)

        # Status Bar (Bottom of Content Area)
        status_frame = ttk.Frame(self.content_area)
        status_frame.pack(side=BOTTOM, fill=X, pady=(10, 0))
        
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
        
        self.progress_bar = ttk.Progressbar(self.content_area, bootstyle="info-striped")
        self.progress_bar.pack(side=BOTTOM, fill=X, pady=(0, 10))

        # Frame to hold the actual view content
        self.view_frame = ttk.Frame(self.content_area)
        self.view_frame.pack(fill=BOTH, expand=YES)

        # Initialize views
        self.views = {}
        self.create_views()
        
        # Show default view
        self.navigate(self.show_dashboard, "Dashboard")

    def create_views(self):
        """Pre-creates all view frames."""
        # Helper to create a view frame
        def create_view(setup_func):
            frame = ttk.Frame(self.view_frame)
            setup_func(frame)
            return frame

        self.views["Dashboard"] = create_view(self.setup_dashboard_view)
        self.views["Duplicates"] = create_view(self.setup_duplicate_finder_view)
        self.views["Large Files"] = create_view(self.setup_large_file_finder_view)
        self.views["Old Files"] = create_view(self.setup_old_file_finder_view)
        self.views["Temp Files"] = create_view(self.setup_temp_file_cleaner_view)
        self.views["Analyzer"] = create_view(self.setup_analyzer_view)
        self.views["Empty Folders"] = create_view(self.setup_empty_folder_cleaner_view)
        self.views["Organizer"] = create_view(self.setup_organizer_view)
        self.views["Renamer"] = create_view(self.setup_renamer_view)

    def navigate(self, command, name):
        """Switches the visible view."""
        # Update button styles
        for btn_name, btn in self.nav_buttons.items():
            if btn_name == name:
                btn.configure(bootstyle="primary")
            else:
                btn.configure(bootstyle="secondary")
        
        # Update Header Title
        self.header_title.config(text=name)

        # Hide all views
        for view in self.views.values():
            view.pack_forget()
            
        # Show selected view
        self.views[name].pack(fill=BOTH, expand=YES)
        
        # Optional: Run specific show logic if needed (not used currently but good for future)
        # command() 

    # --- View Setup Functions ---

    def setup_dashboard_view(self, parent):
        # Title removed (handled by header)
        
        stats_frame = ttk.Frame(parent)
        stats_frame.pack(fill=X, expand=YES, anchor=N)
        
        self.dash_labels = {}
        for i, (key, label_text) in enumerate([
            ("total_size_mb", "Total Size (MB)"),
            ("file_count", "File Count"),
            ("folder_count", "Folder Count")
        ]):
            frame = ttk.LabelFrame(stats_frame, text=label_text, padding=20, bootstyle="info")
            frame.grid(row=0, column=i, padx=10, sticky="ew")
            lbl = ttk.Label(frame, text="-", font=("Segoe UI", 24))
            lbl.pack()
            self.dash_labels[key] = lbl
            
        stats_frame.grid_columnconfigure(0, weight=1)
        stats_frame.grid_columnconfigure(1, weight=1)
        stats_frame.grid_columnconfigure(2, weight=1)

        btn_frame = ttk.Frame(parent, padding=20)
        btn_frame.pack(fill=X, pady=20)
        ttk.Button(btn_frame, text="Refresh Dashboard", command=self.refresh_dashboard, bootstyle="success").pack()

    def setup_duplicate_finder_view(self, parent):
        paned_window = ttk.PanedWindow(parent, orient=HORIZONTAL)
        paned_window.pack(fill=BOTH, expand=YES)

        left_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(left_frame, weight=3)
        right_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(right_frame, weight=1)

        results_frame = ttk.LabelFrame(left_frame, text="Found Duplicates (Grouped)", padding=10)
        results_frame.pack(fill=BOTH, expand=YES)
        self.dup_tree = self.create_results_tree(results_frame, ("File Name", "Path", "Size (KB)", "Modified Date"))
        
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

    def setup_large_file_finder_view(self, parent):
        paned_window = ttk.PanedWindow(parent, orient=HORIZONTAL)
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
        
        self.large_file_preview_labels = self.create_preview_pane(right_frame, "File Preview")
        self.large_files_tree.bind('<<TreeviewSelect>>', lambda e: self.on_file_select(e, self.large_files_tree, 1, self.large_file_preview_labels))

        btn_frame = self.create_button_bar(left_frame, self.start_large_file_scan, lambda: self.delete_selected_from_tree(self.large_files_tree, 1), lambda: self.export_treeview_to_csv(self.large_files_tree))
        btn_frame['run_btn'].config(text="Find Large Files")

    def setup_old_file_finder_view(self, parent):
        paned_window = ttk.PanedWindow(parent, orient=HORIZONTAL)
        paned_window.pack(fill=BOTH, expand=YES)
        left_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(left_frame, weight=3)
        right_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(right_frame, weight=1)

        options_frame = ttk.LabelFrame(left_frame, text="Options", padding=10)
        options_frame.pack(fill=X, pady=(0, 10))
        ttk.Label(options_frame, text="Find files not modified in (days):").pack(side=LEFT, padx=5)
        self.old_days_var = tk.StringVar(value="180")
        ttk.Entry(options_frame, textvariable=self.old_days_var, width=10).pack(side=LEFT)

        results_frame = ttk.LabelFrame(left_frame, text="Old Files Found", padding=10)
        results_frame.pack(fill=BOTH, expand=YES)
        self.old_files_tree = self.create_results_tree(results_frame, ("File Name", "Path", "Size (MB)", "Last Modified"))
        
        self.old_file_preview_labels = self.create_preview_pane(right_frame, "File Preview")
        self.old_files_tree.bind('<<TreeviewSelect>>', lambda e: self.on_file_select(e, self.old_files_tree, 1, self.old_file_preview_labels))

        btn_frame = self.create_button_bar(left_frame, self.start_old_file_scan, lambda: self.delete_selected_from_tree(self.old_files_tree, 1), lambda: self.export_treeview_to_csv(self.old_files_tree))
        btn_frame['run_btn'].config(text="Find Old Files")

    def setup_temp_file_cleaner_view(self, parent):
        paned_window = ttk.PanedWindow(parent, orient=HORIZONTAL)
        paned_window.pack(fill=BOTH, expand=YES)
        left_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(left_frame, weight=3)
        right_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(right_frame, weight=1)

        results_frame = ttk.LabelFrame(left_frame, text="Temporary Files Found", padding=10)
        results_frame.pack(fill=BOTH, expand=YES)
        self.temp_files_tree = self.create_results_tree(results_frame, ("File Name", "Path", "Size (KB)"))
        
        self.temp_file_preview_labels = self.create_preview_pane(right_frame, "File Preview")
        self.temp_files_tree.bind('<<TreeviewSelect>>', lambda e: self.on_file_select(e, self.temp_files_tree, 1, self.temp_file_preview_labels))

        btn_frame = self.create_button_bar(left_frame, self.start_temp_file_scan, lambda: self.delete_selected_from_tree(self.temp_files_tree, 1), lambda: self.export_treeview_to_csv(self.temp_files_tree))
        btn_frame['run_btn'].config(text="Find Temp Files")

    def setup_analyzer_view(self, parent):
        results_frame = ttk.LabelFrame(parent, text="Disk Usage by File Type", padding=10)
        results_frame.pack(fill=BOTH, expand=YES, pady=5)
        self.analyzer_tree = self.create_results_tree(results_frame, ("Extension", "File Count", "Total Size (MB)"))

        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=X, pady=5)
        btn = ttk.Button(button_frame, text="Choose Folder & Analyze", command=self.start_analyzer_scan, bootstyle="primary")
        btn.pack(side=LEFT, expand=YES, fill=X, padx=(0, 5))
        self.run_buttons.append(btn)
        ttk.Button(button_frame, text="Export to CSV", command=lambda: self.export_treeview_to_csv(self.analyzer_tree), bootstyle="secondary-outline").pack(side=LEFT, expand=YES, fill=X)

    def setup_empty_folder_cleaner_view(self, parent):
        log_frame = ttk.LabelFrame(parent, text="Log", padding=10)
        log_frame.pack(fill=BOTH, expand=YES, pady=5)
        self.cleaner_log = ScrolledText(log_frame, wrap=WORD, height=10, autohide=True)
        self.cleaner_log.pack(fill=BOTH, expand=YES)

        btn = ttk.Button(parent, text="Choose Folder & Clean Empties", command=self.start_cleanup, bootstyle="primary")
        btn.pack(fill=X, pady=5)
        self.run_buttons.append(btn)

    def setup_organizer_view(self, parent):
        info_label = ttk.Label(parent, text="This tool will organize files in a selected folder into subfolders (Images, Documents, etc.) based on their extension.", wraplength=600)
        info_label.pack(anchor=W, pady=(0, 20))
        
        log_frame = ttk.LabelFrame(parent, text="Log", padding=10)
        log_frame.pack(fill=BOTH, expand=YES, pady=5)
        self.organizer_log = ScrolledText(log_frame, wrap=WORD, height=10, autohide=True)
        self.organizer_log.pack(fill=BOTH, expand=YES)

        btn = ttk.Button(parent, text="Choose Folder & Organize", command=self.start_organizer, bootstyle="primary")
        btn.pack(fill=X, pady=5)
        self.run_buttons.append(btn)

    def setup_renamer_view(self, parent):
        # File Selection
        sel_frame = ttk.LabelFrame(parent, text="1. Select Files", padding=10)
        sel_frame.pack(fill=X, pady=5)
        
        self.renamer_files = []
        self.renamer_listbox = tk.Listbox(sel_frame, height=5)
        self.renamer_listbox.pack(fill=X, expand=YES, side=LEFT)
        
        btn_sel = ttk.Button(sel_frame, text="Add Files", command=self.add_files_to_renamer, bootstyle="secondary")
        btn_sel.pack(side=LEFT, padx=5, anchor=N)
        
        # Pattern Input
        pat_frame = ttk.LabelFrame(parent, text="2. Define Pattern", padding=10)
        pat_frame.pack(fill=X, pady=5)
        
        ttk.Label(pat_frame, text="Pattern:").pack(side=LEFT)
        self.rename_pattern = tk.StringVar(value="File_{counter}")
        ttk.Entry(pat_frame, textvariable=self.rename_pattern).pack(side=LEFT, fill=X, expand=YES, padx=5)
        ttk.Label(pat_frame, text="Placeholders: {name}, {ext}, {date}, {counter}", font=("Segoe UI", 8)).pack(side=LEFT)

        # Log
        log_frame = ttk.LabelFrame(parent, text="Log", padding=10)
        log_frame.pack(fill=BOTH, expand=YES, pady=5)
        self.renamer_log = ScrolledText(log_frame, wrap=WORD, height=10, autohide=True)
        self.renamer_log.pack(fill=BOTH, expand=YES)

        btn = ttk.Button(parent, text="Start Renaming", command=self.start_renamer, bootstyle="primary")
        btn.pack(fill=X, pady=5)
        self.run_buttons.append(btn)

    # --- Helper Functions ---

    def create_results_tree(self, parent, columns):
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=BOTH, expand=YES)
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
        preview_labels = {}
        fields = ["Name:", "Path:", "Size:", "Created:", "Modified:"]
        for i, field in enumerate(fields):
            ttk.Label(pane, text=field, font=('Segoe UI', 9, 'bold')).grid(row=i, column=0, sticky="ne", padx=5, pady=2)
            preview_labels[field] = ttk.Label(pane, text="", wraplength=200, anchor=W)
            preview_labels[field].grid(row=i, column=1, sticky="nw", padx=5, pady=2)
        pane.grid_columnconfigure(1, weight=1)
        return preview_labels

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
                    if parent_text:
                        writer.writerow([f"--- {parent_text} ---"])
                        for child_id in tree.get_children(item_id):
                            writer.writerow(tree.item(child_id, "values"))
                    else:
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
            for item_id in selected_items:
                if tree.exists(item_id):
                    tree.delete(item_id)
            self.status_label.config(text="Deletion complete.")

    # --- Event Handlers & Logic Wrappers ---

    def show_dashboard(self): pass # Placeholder
    def show_duplicate_finder(self): pass
    def show_large_file_finder(self): pass
    def show_old_file_finder(self): pass
    def show_temp_file_cleaner(self): pass
    def show_analyzer(self): pass
    def show_empty_folder_cleaner(self): pass
    def show_organizer(self): pass
    def show_renamer(self): pass

    def refresh_dashboard(self):
        folder = filedialog.askdirectory(initialdir=self.last_folder, title="Select folder for Dashboard")
        if not folder:
            return
        self.last_folder = folder
        
        def run_stats():
            self.root.after(0, lambda: self.status_label.config(text="Calculating dashboard stats..."))
            stats = logic.get_dashboard_stats(folder)
            self.root.after(0, lambda: self.update_dashboard_ui(stats))
            
        threading.Thread(target=run_stats, daemon=True).start()

    def update_dashboard_ui(self, stats):
        self.dash_labels["total_size_mb"].config(text=f"{stats['total_size_mb']:.2f}")
        self.dash_labels["file_count"].config(text=f"{stats['file_count']:,}")
        self.dash_labels["folder_count"].config(text=f"{stats['folder_count']:,}")
        self.status_label.config(text="Dashboard updated.")

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
        utils.save_settings(settings)

    def load_settings(self):
        settings = utils.load_settings()
        self.root.geometry(settings.get("geometry", "1100x750"))
        theme = settings.get("theme", "dark")
        self.theme_var.set(theme)
        self.toggle_theme()
        self.last_folder = settings.get("last_folder", os.path.expanduser("~"))
        self.min_size_var.set(settings.get("min_size_mb", "100"))

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
        if task_func == logic.find_duplicates:
            self.dup_tree.delete(*self.dup_tree.get_children())
        if task_func == logic.find_large_files:
            self.large_files_tree.delete(*self.large_files_tree.get_children())
        if task_func == logic.analyze_file_types:
            self.analyzer_tree.delete(*self.analyzer_tree.get_children())
        if task_func == logic.clean_empty_folders:
            self.cleaner_log.delete('1.0', tk.END)
        if task_func == logic.find_old_files:
            self.old_files_tree.delete(*self.old_files_tree.get_children())
        if task_func == logic.find_temp_files:
            self.temp_files_tree.delete(*self.temp_files_tree.get_children())
        if task_func == logic.organize_files:
            self.organizer_log.delete('1.0', tk.END)

        thread = threading.Thread(target=task_func, args=(self.progress_queue, self.cancel_event, folder, *args), daemon=True)
        thread.start()

    def start_duplicate_scan(self):
        self.start_task(logic.find_duplicates)

    def start_large_file_scan(self):
        try:
            min_size = int(self.min_size_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Minimum size must be a number.")
            return
        self.start_task(logic.find_large_files, min_size)

    def start_old_file_scan(self):
        try:
            days = int(self.old_days_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Days must be a number.")
            return
        self.start_task(logic.find_old_files, days)

    def start_temp_file_scan(self):
        self.start_task(logic.find_temp_files)

    def start_analyzer_scan(self):
        self.start_task(logic.analyze_file_types)

    def start_cleanup(self):
        self.start_task(logic.clean_empty_folders)
    
    def start_organizer(self):
        self.start_task(logic.organize_files)
    
    def add_files_to_renamer(self):
        files = filedialog.askopenfilenames(title="Select files to rename")
        for f in files:
            self.renamer_files.append(f)
            self.renamer_listbox.insert(END, os.path.basename(f))
            
    def start_renamer(self):
        if not self.renamer_files:
            messagebox.showwarning("No Files", "Please select files to rename.")
            return
        
        pattern = self.rename_pattern.get()
        if not pattern:
            messagebox.showwarning("No Pattern", "Please enter a renaming pattern.")
            return
            
        self.renamer_log.delete('1.0', tk.END)
        self.toggle_controls(is_running=True)
        
        # Renamer logic doesn't take a folder path as the main arg, so we adapt
        thread = threading.Thread(target=logic.batch_rename_files, args=(self.progress_queue, self.cancel_event, self.renamer_files, pattern), daemon=True)
        thread.start()

    def smart_select_duplicates(self):
        if self.is_running: return
        
        current_selection = self.dup_tree.selection()
        if current_selection:
            self.dup_tree.selection_remove(current_selection)

        items_to_select = []
        for group_id in self.dup_tree.get_children():
            children = self.dup_tree.get_children(group_id)
            if len(children) > 1:
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
            elif msg_type == "old_file_result":
                self.old_files_tree.insert("", END, values=message["data"])
            elif msg_type == "temp_file_result":
                self.temp_files_tree.insert("", END, values=message["data"])
            elif msg_type == "analyzer_result":
                self.analyzer_tree.insert("", END, values=message["data"])
            elif msg_type == "cleaner_log":
                self.cleaner_log.insert(END, message["data"] + "\n")
                self.cleaner_log.see(END)
            elif msg_type == "organizer_log":
                self.organizer_log.insert(END, message["data"] + "\n")
                self.organizer_log.see(END)
            elif msg_type == "renamer_log":
                self.renamer_log.insert(END, message["data"] + "\n")
                self.renamer_log.see(END)
            elif msg_type == "done":
                self.progress_bar.stop()
                self.progress_bar["value"] = 0
                self.status_label.config(text="Ready")
                self.toggle_controls(is_running=False)
                messagebox.showinfo("Done", message["message"])
                
                # If renamer finished, clear list
                if "Batch rename complete" in message["message"]:
                    self.renamer_files = []
                    self.renamer_listbox.delete(0, END)
                    
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
