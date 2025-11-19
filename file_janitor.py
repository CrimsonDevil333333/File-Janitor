import ttkbootstrap as ttk
from gui import FileJanitorApp

if __name__ == "__main__":
    root = ttk.Window(themename="superhero")
    app = FileJanitorApp(root)
    root.mainloop()