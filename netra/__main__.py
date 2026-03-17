"""
netra/__main__.py
Allows `python3 -m netra` to launch the NETRA CLI.
"""
import sys
import runpy

def main() -> None:
    """Entry point for `netra` console script and `python3 -m netra`."""
    sys.argv[0] = "netra"
    runpy.run_path("netra.py", run_name="__main__")

if __name__ == "__main__":
    main()
