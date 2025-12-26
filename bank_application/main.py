#!/usr/bin/env python3
"""
Bank Manager - Main Entry Point
"""
import sys
import os

# Add the current directory to path to ensure imports work correctly
# when running from the root directory or the package directory.
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from ui import LoginWindow

def main():
    """Main function"""
    app = LoginWindow()
    app.run()

if __name__ == '__main__':
    main()
