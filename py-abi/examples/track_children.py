import sys
import time
from py_query_system_info import start_tracking_children

if len(sys.argv) < 2:
    print("Usage: python track_children.py <pid>")
    sys.exit(1)

pid = int(sys.argv[1])
print(f"Tracking children of PID: {pid}")

def on_child_process(child):
    print("\n[New Child Process]")
    print(f"  PID: {child['pid']}")
    print(f"  PPID: {child['ppid']}")
    print(f"  Name: {child['name']}")
    print(f"  Command: {' '.join(child['cmdline'])}")
    print(f"  Exe: {child['exe_path']}")

tracker = start_tracking_children(pid, on_child_process)
print("Tracking started. Press Ctrl+C to stop...\n")

try:
    time.sleep(60)
finally:
    tracker.stop()
    print("\nTracking stopped.")
