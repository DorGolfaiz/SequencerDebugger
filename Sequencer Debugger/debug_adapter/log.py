import threading
import traceback
import os
_debug_lock = threading.Lock()

DEBUG_FILE = os.path.join(os.path.dirname(__file__), '__debug_output__.txt')
DEBUG_FLAG = False

def debug(msg):
    if DEBUG_FLAG:
         with _debug_lock:
             open(DEBUG_FILE, 'a+').write(msg)


def debug_exception(msg=None):
    if DEBUG_FLAG:
         with _debug_lock:
             if msg:
                 open(DEBUG_FILE, 'a+').write(msg)
                 open(DEBUG_FILE, 'a+').write(traceback.format_exc())
