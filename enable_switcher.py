from pathlib import Path
from ctypes import windll
import shutil
import time
import sys
import os

BACKUPS_PATH = Path.cwd() / "backup"


def bulk_exec(*command: str):
    for i in command:
        os.system(i)


if not windll.shell32.IsUserAnAdmin():
    print("Please run script as admin!")
    sys.exit(1)
if not BACKUPS_PATH.exists() and BACKUPS_PATH.is_dir():
    print("Backup directory does not exist!")
    sys.exit(1)

os.system("taskkill /F /IM explorer.exe")
time.sleep(2)

for item in BACKUPS_PATH.iterdir():
    if not item.is_dir():
        continue

    info_path = item / "info.txt"
    if not (info_path.exists() and info_path.is_file()):
        continue
    info = info_path.read_text()

    bulk_exec(
        f'takeown /F "{info}" /A',
        f'icacls "{info}" /grant:r "*S-1-5-32-544":f'
    )
    shutil.copyfile(str(item / "InputSwitch.dll"), info)
    bulk_exec(
        f'icacls "{info}" /setowner "NT SERVICE\\TrustedInstaller" /C /L /Q',
        f'icacls "{info}" /grant:r "NT SERVICE\\TrustedInstaller":rx',
        f'icacls "{info}" /grant:r "*S-1-5-32-544":rx'
    )

os.system("start %windir%\\explorer.exe")
print("Done!")
