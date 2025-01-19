import time, threading, guardshield, ctypes, win32api
from ctypes import windll, wintypes
import pymem
from ui.interface import IncognitoInterface
from misc.bootstrapper import Bootstrapper, SystemInfo

kernel32, ntdll, user32 = windll.kernel32, windll.ntdll, windll.user32

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_void_p),
        ('AllocationBase', ctypes.c_void_p),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD),
    ]

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_READWRITE = 0x04

def get_memory_regions(handle):
    mbi = MEMORY_BASIC_INFORMATION()
    address, regions = 0, []
    while ctypes.windll.kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
            regions.append({'BaseAddress': mbi.BaseAddress, 'RegionSize': mbi.RegionSize, 'Protect': mbi.Protect})
        address += mbi.RegionSize
    return regions

def wsbypasstest():
    time.sleep(5) # for bloxstrap auto start thingy
    process = None
    while process is None:
        try: process = pymem.Pymem('RobloxPlayerBeta.exe')
        except: time.sleep(0.1)
    watched_memory_pool = None
    while watched_memory_pool is None:
        for mem_region in get_memory_regions(process.process_handle):
            if mem_region['Protect'] == PAGE_READWRITE and mem_region['RegionSize'] == 0x200000:
                watched_memory_pool = mem_region['BaseAddress']
                print(f"[info] Found watched memory pool at 0x{watched_memory_pool:x}, {mem_region['RegionSize']} bytes")
                break
        if not watched_memory_pool: time.sleep(0.1)
    process.write_int(watched_memory_pool + 0x208, 0x20)
    print(f"[info] modified memory at 0x{watched_memory_pool + 0x208:x}")
    input("press enter to exit")

def error_box(content: str, style: int = 0):
    return user32.MessageBoxW(0, content, "Incognito", style | 0x10 | 0x1000 | 0x10000 | 0x40000 | 0x200000)

def erase_pe_header():
    base_addy = ctypes.c_ulonglong(win32api.GetModuleHandle(None))
    old_protect = wintypes.DWORD(0)

    kernel32.VirtualProtect(ctypes.pointer(base_addy), 4096, 0x04, ctypes.pointer(old_protect))
    ctypes.memset(ctypes.pointer(base_addy), 4096, ctypes.sizeof(base_addy))

def hide_threads():
    process_id = kernel32.GetCurrentProcessId()

    process_handle = kernel32.OpenProcess(0x1F0FFF, False, process_id)
    if process_handle is None:
        return

    thread_id = kernel32.GetCurrentThreadId()
    thread_handle = kernel32.OpenThread(0x1F03FF, False, thread_id)
    if thread_handle is None:
        kernel32.CloseHandle(thread_id)
        return

    ntdll.NtSetInformationThread(
        thread_handle, 0x11, ctypes.byref((ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int))
    )

    kernel32.CloseHandle(thread_handle)
    kernel32.CloseHandle(process_handle)

def watchdog_checker():
    watchdog = guardshield.Security(
        anti_debugger=True,
        detect_vm=True,
        detect_sandbox=True
    )

    erase_pe_header()
    hide_threads()

    while True:
        time.sleep(1/20)

        if watchdog.check_debug():
            interface.main_window.hide()
            pressed_btn = error_box("STOP TOUCHING ME INSIDES YOU FILTHY ANIMAL!", 0x01)

            if pressed_btn == 1: # ok
                watchdog.force_kill()
            elif pressed_btn == 2: # cancel
                error_box("We'll see about that >:)")
                watchdog.crash_pc()

if __name__ == "__main__":
    hwnd = kernel32.GetConsoleWindow()
    user32.ShowWindow(hwnd, 0)
    
    watchdog_thread = threading.Thread(target=watchdog_checker, daemon=True)
    watchdog_thread.start()

    """
    bootStrapper = Bootstrapper()
    message = bootStrapper.run()
    print(message) # we use this message to display on ui
    """
    wsbypasstest()
    global interface
    interface = IncognitoInterface()
    interface.start()
