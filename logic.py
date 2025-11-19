import os
import hashlib
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
import time

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

def find_old_files(progress_queue, cancel_event, folder_path, days_threshold):
    """Finds files that haven't been modified in a long time."""
    files = list(Path(folder_path).rglob("*"))
    total_files = len(files) if files else 1
    threshold_date = datetime.now() - timedelta(days=days_threshold)
    
    for i, path in enumerate(files):
        if cancel_event.is_set():
            progress_queue.put({"type": "done", "message": "Cancelled"})
            return
        if not path.is_file():
            continue
        progress_queue.put({"type": "progress", "value": (i/total_files)*100, "status": f"Scanning: {path.name}"})
        try:
            stat = path.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime)
            if mtime < threshold_date:
                size_mb = stat.st_size / (1024 * 1024)
                progress_queue.put({"type": "old_file_result", "data": (path.name, str(path.parent), f"{size_mb:.2f}", mtime.strftime('%Y-%m-%d'))})
        except FileNotFoundError:
            continue
    progress_queue.put({"type": "done", "message": "Old file scan complete!"})

def find_temp_files(progress_queue, cancel_event, folder_path):
    """Finds temporary files."""
    temp_extensions = {'.tmp', '.log', '.bak', '.old', '.swp'}
    temp_names = {'thumbs.db', 'desktop.ini', '.ds_store'}
    
    files = list(Path(folder_path).rglob("*"))
    total_files = len(files) if files else 1
    
    for i, path in enumerate(files):
        if cancel_event.is_set():
            progress_queue.put({"type": "done", "message": "Cancelled"})
            return
        if not path.is_file():
            continue
        progress_queue.put({"type": "progress", "value": (i/total_files)*100, "status": f"Scanning: {path.name}"})
        
        is_temp = False
        if path.suffix.lower() in temp_extensions:
            is_temp = True
        elif path.name.lower() in temp_names:
            is_temp = True
            
        if is_temp:
            try:
                size_kb = path.stat().st_size / 1024
                progress_queue.put({"type": "temp_file_result", "data": (path.name, str(path.parent), f"{size_kb:.2f}")})
            except FileNotFoundError:
                continue
                
    progress_queue.put({"type": "done", "message": "Temp file scan complete!"})

def get_dashboard_stats(folder_path):
    """Calculates quick stats for the dashboard."""
    total_size = 0
    file_count = 0
    folder_count = 0
    
    # This might be slow for large drives, so we might need to run it in a thread or limit depth
    # For now, let's just do a quick walk
    for dirpath, dirnames, filenames in os.walk(folder_path):
        folder_count += len(dirnames)
        file_count += len(filenames)
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total_size += os.path.getsize(fp)
            except OSError:
                pass
                
    return {
        "total_size_mb": total_size / (1024 * 1024),
        "file_count": file_count,
        "folder_count": folder_count
    }

def organize_files(progress_queue, cancel_event, folder_path):
    """Organizes files into subfolders based on extension."""
    files = [p for p in Path(folder_path).iterdir() if p.is_file()]
    total_files = len(files)
    
    # Define categories
    categories = {
        "Images": {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp'},
        "Documents": {'.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.xls', '.xlsx', '.ppt', '.pptx'},
        "Audio": {'.mp3', '.wav', '.aac', '.flac', '.ogg'},
        "Video": {'.mp4', '.mkv', '.avi', '.mov', '.wmv'},
        "Archives": {'.zip', '.rar', '.7z', '.tar', '.gz'},
        "Code": {'.py', '.js', '.html', '.css', '.java', '.cpp', '.c', '.h', '.json', '.xml'},
        "Executables": {'.exe', '.msi', '.bat', '.sh'}
    }
    
    for i, path in enumerate(files):
        if cancel_event.is_set():
            progress_queue.put({"type": "done", "message": "Cancelled"})
            return
            
        progress_queue.put({"type": "progress", "value": (i/total_files)*100, "status": f"Organizing: {path.name}"})
        
        ext = path.suffix.lower()
        dest_folder_name = "Others"
        for category, extensions in categories.items():
            if ext in extensions:
                dest_folder_name = category
                break
        
        dest_folder = Path(folder_path) / dest_folder_name
        try:
            dest_folder.mkdir(exist_ok=True)
            new_path = dest_folder / path.name
            
            # Handle duplicates by renaming
            if new_path.exists():
                timestamp = int(time.time())
                new_path = dest_folder / f"{path.stem}_{timestamp}{path.suffix}"
                
            path.rename(new_path)
            progress_queue.put({"type": "organizer_log", "data": f"Moved {path.name} -> {dest_folder_name}/"})
        except Exception as e:
            progress_queue.put({"type": "organizer_log", "data": f"Error moving {path.name}: {e}"})
            
    progress_queue.put({"type": "done", "message": "Organization complete!"})

def batch_rename_files(progress_queue, cancel_event, files_to_rename, pattern):
    """Renames a list of files based on a pattern."""
    total_files = len(files_to_rename)
    
    for i, file_path_str in enumerate(files_to_rename):
        if cancel_event.is_set():
            progress_queue.put({"type": "done", "message": "Cancelled"})
            return
            
        path = Path(file_path_str)
        if not path.exists():
            continue
            
        progress_queue.put({"type": "progress", "value": (i/total_files)*100, "status": f"Renaming: {path.name}"})
        
        # Simple pattern replacement
        # Supported placeholders: {name}, {ext}, {date}, {counter}
        new_name = pattern
        new_name = new_name.replace("{name}", path.stem)
        new_name = new_name.replace("{ext}", path.suffix)
        new_name = new_name.replace("{date}", datetime.now().strftime("%Y-%m-%d"))
        
        # Handle counter if present
        if "{counter}" in new_name:
            # This is a bit tricky for batch processing without global state, 
            # so we'll just use the loop index + 1
            new_name = new_name.replace("{counter}", str(i + 1).zfill(3))
            
        # Ensure extension is preserved if not in pattern
        if path.suffix and path.suffix not in new_name:
             new_name += path.suffix

        try:
            new_path = path.parent / new_name
            path.rename(new_path)
            progress_queue.put({"type": "renamer_log", "data": f"Renamed {path.name} -> {new_name}"})
        except Exception as e:
            progress_queue.put({"type": "renamer_log", "data": f"Error renaming {path.name}: {e}"})
            
    progress_queue.put({"type": "done", "message": "Batch rename complete!"})
