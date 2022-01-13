# from sys import exit as sysExit
# from time import sleep
# from binascii import unhexlify, hexlify
# from shutil import copyfile
# from pathlib import Path as pathLibPath
# from os import path as osPath, makedirs as osMakedirs, environ as env, listdir, system as cmd

from typing import List
from pathlib import Path
from ctypes import windll
import logging as log
import shutil
import time
import sys
import os

WIN_PATH = Path(os.environ["WINDIR"])
SYS32_PATH = (WIN_PATH / "System32").resolve()
WIN_SXS_PATH = WIN_PATH / "WinSxS"
EXEC_PATH = Path(__file__).parent.absolute()
BACKUPS_PATH = EXEC_PATH / "backup"
DLL_NAME = "InputSwitch.dll"


def bulk_exec(*command: str):
    for i in command:
        os.system(i)


class ScriptException(Exception):
    ...


class FileNotExists(ScriptException):
    path: Path

    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(f"{path} not exists")


class Patch:
    dirs: List[Path]

    def __init__(self) -> None:
        self.dirs = [SYS32_PATH]
        for item in WIN_SXS_PATH.iterdir():
            if not item.is_dir():
                continue
            if "inputswitch" in item.name:
                self.dirs.append(item)

    def run(self):
        log.info("Процесс патчинга начинается. Отключение explorer.exe...")
        os.system("taskkill /F /IM explorer.exe")
        time.sleep(2)
        for path in self.dirs:
            try:
                self.patch_dir(path)
            except ScriptException as e:
                ...  # TODO
        os.system("start %windir%\\explorer.exe")

        if self.has_errors:
            print("Патч завершился с ошибками. Это есть не добрый знак. Попытайтесь откатить изменения с помощью \"python offPatch.py\"")
            sys.exit(1)
        else:
            print("Done!")
            sys.exit(0)

#     def warn(self, warntext):
#         print(f"WARN! FilePath: {self.filePath} : {warntext}")
#
#     def error(self, error):
#         self.hasErrors = True
#         print(f"ERROR! FilePath: {self.filePath} : {error}")

    def patch_dir(self, path: Path):
        dll_path = path / DLL_NAME
        if not dll_path.exists():
            raise FileNotExists(dll_path)

        bulk_exec(
            # set group of admins as the owners of file
            f'takeown /F "{dll_path}" /A',
            # give the administrator group full access to this file
            f'icacls "{dll_path}" /grant:r "*S-1-5-32-544":f'
        )

        # backup
        backup_path = BACKUPS_PATH / path.name
        if not backup_path.exists():
            backup_path.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(dll_path), str(backup_path / DLL_NAME))
            (backup_path / "info.txt").write_text(dll_path)

        self.processPatch()
        bulk_exec(
            # return the rights to trusted installer
            f'icacls "{dll_path}" /setowner "NT SERVICE\\TrustedInstaller" /C /L /Q',
            # give administrators and trusted installer read and execute permissions
            f'icacls "{dll_path}" /grant:r "NT SERVICE\\TrustedInstaller":rx',
            f'icacls "{dll_path}" /grant:r "*S-1-5-32-544":rx'
        )

    def processPatch(self):

        with open(self.filePath, 'rb') as f:

            hexdata = hexlify(f.read()).decode("utf-8")

            i = 0
            pointer = 0
            hexAsList = []

            for h in hexdata:

                if i % 2 == 0 and i != 0: pointer += 1

                if not pointer < len(hexAsList): hexAsList.append(h)
                else: hexAsList[pointer] += h

                i += 1

            i = 0
            inARow = 0
            maxArea = 40
            res = 0

            for h in hexAsList:

                if inARow >= 5:

                    if maxArea > 0:

                        maxArea -= 1

                        hexAsList[i] = "90"

                        if h == "33" and inARow == 5:

                            inARow += 1

                        elif h == "c0" and inARow == 6:

                            inARow += 1

                        elif (h == "48" or h == "8b") and inARow == 7:

                            # final

                            hexAsList[i] = h
                            hexAsList[i - 1] = "c0"
                            hexAsList[i - 2] = "33"

                            res = 1

                            break

                    else:

                        break

                elif h == "ff" and inARow == 0:
                    inARow += 1
                elif h == "ff" and inARow == 1:
                    inARow += 1
                elif h == "83" and inARow == 2:
                    inARow += 1
                elif h == "f8" and inARow == 3:
                    inARow += 1
                elif h == "ff" and inARow == 4:
                    inARow += 1
                else:
                    inARow = 0

                i += 1

            if res == 0:
                self.error("cant patch this dll!")
                return False

            with open(self.filePath, 'wb') as fout:
                for h in hexAsList:
                    fout.write(unhexlify(h))

            print(self.filePath + ": SUCCESSFUL PATCHING")
            return True


if __name__ == "__main__":
    if not windll.shell32.IsUserAnAdmin():
        print("Please run script as admin!")
        sys.exit(1)
    Patch().run()
