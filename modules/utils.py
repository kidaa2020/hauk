import sys
import os

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

def color(text, c):
    return f"{c}{text}{Colors.RESET}"

def banner():
    print(color(r"""
  ____                      _   _               _    
 |  _ \ ___  ___ ___  _ __ | | | | __ ___      | | __
 | |_) / _ \/ __/ _ \| '_ \| |_| |/ _` \ \ /\ / |/ /
 |  _ <  __/ (_| (_) | | | |  _  | (_| |\ V  V /|   < 
 |_| \_\___|\___\___/|_| |_|_| |_|\__,_| \_/\_/ |_|\_\
    """, Colors.CYAN))
    print(color(" Advanced Pentesting & Bug Bounty Automation Tool", Colors.MAGENTA))
    print(color(" " + "-"*50, Colors.BLUE))

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path

def save_file(path, content):
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(content)
