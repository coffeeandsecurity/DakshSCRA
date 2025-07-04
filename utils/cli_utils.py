# Standard libraries
import itertools
import sys
import threading
import time

# Third-party libraries
from colorama import Fore, Style

# Local application imports
from state import constants
from utils.config_utils import get_tool_version



def toolUsage(option):
    cyan = Fore.CYAN
    yellow = Fore.YELLOW
    reset = Style.RESET_ALL

    if option == 'invalid_dir':
        print(f"\n{Fore.RED}[!] Invalid or missing target directory.{reset}\n")
        print("Example:")
        print(f"  {yellow}dakshsca.py -r php -t /path/to/source{reset}")
        print(f"  {yellow}dakshsca.py -r php,java -t ./project/src{reset}")
        return

    version = get_tool_version()
    author_banner = constants.AUTHOR_BANNER.format(version=version)
    print(author_banner)

    print(f"{cyan}Usage:{reset}")
    print(f"  {yellow}dakshsca.py [options]{reset}\n")

    print(f"{cyan}Options:{reset}")
    print(f"  {yellow}-r <rule>{reset}         Specify platform(s) (e.g. php,java,cpp) or use {yellow}auto{reset}")
    print(f"  {yellow}-f <filetype>{reset}     (Optional) Override default filetypes for scanning")
    print(f"  {yellow}-t <dir>{reset}          Target source code directory (required)")
    print(f"  {yellow}-v{reset}                Set verbosity level (-v, -vv, -vvv)")
    print(f"  {yellow}-recon{reset}            Perform platform detection only or with rule scanning")
    print(f"  {yellow}-estimate{reset}         Estimate code review effort based on codebase size")
    print(f"  {yellow}-l [R|RF]{reset}         List available rules [R] or rules + filetypes [RF]")
    print(f"  {yellow}-h, --help{reset}        Show this help message\n")

    print(f"{cyan}Examples:{reset}")
    print(f"  {yellow}dakshsca.py -r php -t ./src{reset}")
    print(f"  {yellow}dakshsca.py -r php,cpp -vv -t /path/to/code{reset}")
    print(f"  {yellow}dakshsca.py -r auto -t ./codebase{reset}")
    print(f"  {yellow}dakshsca.py -recon -t ./api{reset}")
    print(f"  {yellow}dakshsca.py -recon -r java -t ./javaapp{reset}")
    print(f"  {yellow}dakshsca.py -r dotnet -f dotnet -t ./dotnetapp{reset}")
    print(f"  {yellow}dakshsca.py -l RF{reset}     # View supported platform rules and file types\n")

    print(f"{cyan}Notes:{reset}")
    print(f"  • If {yellow}-f{reset} is not provided, default filetypes for the selected platform(s) will be used.")
    print(f"  • Use {yellow}-r auto{reset} to detect file types and auto-apply all relevant platform rules.")
    print(f"  • Use {yellow}-recon{reset} alone to detect technology stack without scanning.")


def section_print(message):
    print()
    print(message)


_spinner_thread = None
_spinner_running = False

def spinner(mode):
    global _spinner_thread, _spinner_running

    if mode == "start":
        def spin():
            while _spinner_running:
                for ch in "|/-\\":
                    sys.stdout.write(ch)
                    sys.stdout.flush()
                    time.sleep(0.1)
                    sys.stdout.write("\b")
        _spinner_running = True
        _spinner_thread = threading.Thread(target=spin)
        _spinner_thread.start()

    elif mode == "stop":
        _spinner_running = False
        if _spinner_thread:
            _spinner_thread.join()
        # Clear entire line cleanly
        sys.stdout.write("\r" + " " * 80 + "\r")  # Clear the full line
        sys.stdout.flush()
