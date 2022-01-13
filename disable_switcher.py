from typing import List
from binascii import unhexlify, hexlify
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
    path: Path
    type: int

    def __init__(self, path: Path, text: str) -> None:
        self.path = path
        super().__init__(text)


class FileNotExists(ScriptException):
    type: log.WARN

    def __init__(self, path: Path) -> None:
        super().__init__(path, "file not exists!")


class UnpatchableDLL(ScriptException):
    type: log.ERROR

    def __init__(self, path: Path) -> None:
        super().__init__(path, "cant patch this dll!")


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
        has_errors = False
        log.info("Процесс патчинга начинается. Отключение explorer.exe...")
        os.system("taskkill /F /IM explorer.exe")
        time.sleep(2)

        for path in self.dirs:
            try:
                self.patch_dir(path)
            except ScriptException as e:
                has_errors = True
                log.log(
                    e.type,
                    f"{e.path} : {e}"
                )
        os.system("start %windir%\\explorer.exe")

        if has_errors:
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

        self.patch_dll(dll_path)
        bulk_exec(
            # return the rights to trusted installer
            f'icacls "{dll_path}" /setowner "NT SERVICE\\TrustedInstaller" /C /L /Q',
            # give administrators and trusted installer read and execute permissions
            f'icacls "{dll_path}" /grant:r "NT SERVICE\\TrustedInstaller":rx',
            f'icacls "{dll_path}" /grant:r "*S-1-5-32-544":rx'
        )

    def patch_dll(self, dll_path: Path):
        hexdata = (
            hexlify(dll_path.read_bytes())
            .decode("utf-8")
        )

        pointer = 0
        hex_list = []
        for i, h in enumerate(hexdata):
            if not i & 1 and i != 0:
                pointer += 1
            if pointer < len(hex_list):
                hex_list[pointer] += h
            else:
                hex_list.append(h)

        in_row = 0
        max_area = 40
        res = 0
        for i, h in enumerate(hex_list):
            if in_row >= 5:
                if max_area <= 0:
                    break

                max_area -= 1
                hex_list[i] = "90"

                if (
                    (in_row == 5 and h == "33")
                    or (in_row == 6 and h == "c0")
                ):
                    in_row += 1
                elif in_row == 7 and h in ("48", "8b"):
                    # final
                    hex_list[i] = h
                    hex_list[i - 1] = "c0"
                    hex_list[i - 2] = "33"
                    res = 1
                    break

            elif (
                (in_row == 0 and h == "ff")
                or (in_row == 1 and h == "ff")
                or (in_row == 2 and h == "83")
                or (in_row == 3 and h == "f8")
                or (in_row == 4 and h == "ff")
            ):
                in_row += 1
            else:
                in_row = 0

            if res == 0:
                raise UnpatchableDLL(dll_path)

            with open(dll_path, "wb") as f:
                for h in hex_list:
                    f.write(unhexlify(h))

            log.info(f"{dll_path} : SUCCESSFUL PATCHING")


if __name__ == "__main__":
    if not windll.shell32.IsUserAnAdmin():
        print("Please run script as admin!")
        sys.exit(1)
    Patch().run()
