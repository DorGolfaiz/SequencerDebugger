import os
import sys
from urllib.parse import quote


def get_pid():
    return os.getpid()


def quote_smart(s, safe='/'):
    return quote(s, safe)


def to_string(x):
    if isinstance(x, str):
        return x
    else:
        return str(x)


def get_filesystem_encoding():
    """
    Note: there's a copy of this method in interpreterInfo.py
    """
    try:
        ret = sys.getfilesystemencoding()
        if not ret:
            raise RuntimeError('Unable to get encoding.')
        return ret
    except:
        pass

        # Only available from 2.3 onwards.
        if sys.platform == 'win32':
            return 'mbcs'
        return 'utf-8'


def get_threads():
    return [0]
    # return threading.enumerate()


def get_main_thread():
    return None
    # return threading.main_thread()


def get_thread_unique_id(thread):
    return 0
    # return thread.native_id


def get_thread_name(thread):
    return 'MainThread'
    # return thread.getName()
