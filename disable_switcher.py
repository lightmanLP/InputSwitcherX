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
import time
import sys
import os

WIN_PATH = Path(os.environ["WINDIR"])
SYS32_PATH = (WIN_PATH / "System32").resolve()
WIN_SXS_PATH = WIN_PATH / "WinSxS"
EXEC_PATH = Path(__file__).parent.absolute()


def bulk_exec(*command: str):
    for i in command:
        os.system(i)


class Patch:
    dirs: List[Path]

    def __init__(self) -> None:
        self.mainFileName = "InputSwitch.dll"
        self.hasErrors = False

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
        for dir in self.dirs:
            self.do(dir)
        os.system("start %windir%\\explorer.exe")

        if self.hasErrors is True:
            print("Патч завершился с ошибками. Это есть не добрый знак. Попытайтесь откатить изменения с помощью \"python offPatch.py\"")
            sys.exit(1)

        else:
            print("Done!")
            sys.exit(0)

    def warn(self, warntext):
        print(f"WARN! FilePath: {self.filePath} : {warntext}")

    def error(self, error):
        self.hasErrors = True
        print(f"ERROR! FilePath: {self.filePath} : {error}")

    def do(self, dir):
        basename = osPath.basename(dir)
        self.filePath = osPath.join(dir, self.mainFileName)
        if not isExists(self.filePath):
            self.warn("not exists")
            return

        # set group of admins as the owners of file
        cmd("takeown /F \"" + self.filePath + "\" /A")

        # give the administrator group full access to this file
        cmd("icacls \"" + self.filePath + "\" /grant:r \"*S-1-5-32-544\":f")

        # backup
        if not isExists("./backup/" + basename):

            backupPath = osPath.join(self.thisPath, "backup", basename, self.mainFileName)

            make_dirs("./backup/" + basename)
            copyfile(self.filePath, backupPath)

            f = open(osPath.join(self.thisPath, "backup", basename, "info.txt"), "a")
            f.write(self.filePath)
            f.close()


        status = self.processPatch()

        # return the rights to trusted installer
        cmd("icacls \"" + self.filePath + "\" /setowner \"NT SERVICE\TrustedInstaller\" /C /L /Q")

        # give administrators and trusted installer read and execute permissions
        cmd("icacls \"" + self.filePath + "\" /grant:r \"NT SERVICE\TrustedInstaller\":rx")
        cmd("icacls \"" + self.filePath + "\" /grant:r \"*S-1-5-32-544\":rx")


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
