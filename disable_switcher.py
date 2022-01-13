from typing import List, Dict
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
INROW_REPLACE_TRIGGERS: Dict[int, str] = {
    0: "ff",
    1: "ff",
    2: "83",
    3: "f8",
    4: "ff",
    5: "33",
    6: "c0",
}


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
    type = log.WARN

    def __init__(self, path: Path) -> None:
        super().__init__(path, "file not exists!")


class UnpatchableDLL(ScriptException):
    type = log.ERROR

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
            log.info(
                "Патч завершился с ошибками. Это есть не добрый знак.\n"
                'Попытайтесь откатить изменения с помощью "python enable_switcher.py"'
            )
            sys.exit(1)
        else:
            log.info("Done!")
            sys.exit(0)

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
            (backup_path / "info.txt").write_text(str(dll_path))

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
        hex_list: List[str] = []
        for i, h in enumerate(hexdata):
            if not i & 1 and i != 0:
                pointer += 1
            if pointer < len(hex_list):
                hex_list[pointer] += h
            else:
                hex_list.append(h)

        in_row = 0
        max_area = 40
        res = False
        for i, h in enumerate(hex_list):
            if in_row >= 5:
                if max_area <= 0:
                    log.debug("max area exceeded")
                    break
                max_area -= 1
                hex_list[i] = "90"

            if INROW_REPLACE_TRIGGERS.get(in_row, "NOVAL") == h:
                in_row += 1

            elif in_row == 7 and h in ("48", "8b"):
                # final
                hex_list[i] = h
                hex_list[i - 1] = "c0"
                hex_list[i - 2] = "33"
                res = True
                break

            else:
                in_row = 0

        if not res:
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
