import os
import sys

def get_resource_path(relative_path):
    """
    Get the absolute path to a resource.
    Works for standard Python development and for PyInstaller compiled .exe files.
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        # If not running as an .exe, use the directory of the current working script
        # You can also use os.path.abspath(".") if your main script runs from a different root
        base_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(base_path, relative_path)