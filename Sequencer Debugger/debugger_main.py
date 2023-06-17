import sys
import os
import time
import threading
import traceback
import queue
from pathlib import Path
from debug_adapter import base_schema, utils
from debug_adapter.command_processor import CommandProcessor
from debug_adapter import log
from debug_adapter.log import debug, debug_exception
from debugger.debugger_api import DebuggerApi
from debugger.debugger_utils import State

class ReaderThread(threading.Thread):
    """ reader thread reads and dispatches commands in an infinite loop """
    MAX_BODY_SIZE = 0xFFFFFF

    def __init__(self, stream_to_read_from, main_db):
        threading.Thread.__init__(self)
        self._reader = stream_to_read_from
        self.main_db = main_db
        self._kill_received = False
        self.setName("Reader")
        self.command_processor = main_db.command_processor

    def kill_thread(self):
        self._kill_received = True

    def _read_line(self):
        line = b""
        while True:
            try:
                line += self._reader.readline()
            except Exception as exc:
                debug(f'Error while trying to readline, err:{str(exc)}')
                raise Exception
            if not line:
                debug(f'No more lines to read')
                raise Exception
            if line.endswith(b"\r\n"):
                line = line[0:-2]
                return line

    def _read(self, size):
        raw_chunks = []
        while size > 0:
            try:
                chunk = self._reader.read(size)
                if not chunk:
                    raise EOFError
            except Exception as exc:
                debug('No More Messages')

            raw_chunks.append(chunk)
            size -= len(chunk)
        assert size == 0
        return raw_chunks

    def run(self):
        try:
            # TODO: Termination
            debug("Reader Thread started \n")
            while True:
                raw_chunks = []
                headers = {}
                # Reading headers till getting empty line
                while True:
                    try:
                        line = self._read_line()
                    except Exception:
                        raw = "".join(raw_chunks)
                        debug(f'Error while reading message, headers:{headers} raw : {raw}')

                    raw_chunks += [line, b"\n"]
                    if line == b"":
                        break

                    key, _, value = line.partition(b":")
                    headers[key] = value

                try:
                    length = int(headers[b"Content-Length"])
                    if not (0 <= length <= self.MAX_BODY_SIZE):
                        raise ValueError
                except (KeyError, ValueError):
                    debug(f'Content-Length is missing or invalid')
                    debug(f'Error while reading message, headers:{headers} raw : {raw}')

                body_start = len(raw_chunks)
                body_remaining = length
                raw_chunks += self._read(body_remaining)

                body = b"".join(raw_chunks[body_start:])
                try:
                    body = body.decode("utf-8")
                except Exception:
                    debug_exception()

                self.command_processor.process_command(self.main_db, body)

        except Exception as e:
            exc = traceback.format_exc()
            self.command_processor.handle_termination_event(self.main_db,
                                                            f'Fatal Error (Reader Exit) \nException:\n{exc}')
            if not self._kill_received:
                if sys is not None and debug_exception is not None:  # Could happen at interpreter shutdown
                    debug_exception()

        finally:
            debug('ReaderThread: exit')


class WriterThread(threading.Thread):
    """ writer thread writes out the commands in an infinite loop """

    def __init__(self, stream_to_write_to, main_db):
        threading.Thread.__init__(self)
        self.main_db = main_db
        self._writer = stream_to_write_to
        self.setName("Writer")
        self._cmd_queue = queue.Queue()
        self.timeout = 0.1
        self._kill_received = False

    def add_command(self, cmd):
        if not self._kill_received:

            self._cmd_queue.put(cmd, False)

    def run(self):
        """ just loop and write responses """
        debug("Writer Thread started\n")
        try:

            while True:
                try:
                    try:
                        cmd = self._cmd_queue.get(True, 0.1)
                    except queue.Empty:
                        if self._kill_received:
                            debug('WriterThread: kill_received ')
                            return  # break if queue is empty and _kill_received
                        else:
                            continue
                except:
                    return

                self.write(cmd.as_bytes())

                time.sleep(self.timeout)
        except Exception:
            debug_exception()
        finally:
            debug('WriterThread: exit')

    def write(self, body):
        writer = self._writer
        if not isinstance(body, bytes):
            body = body.encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n"
        header = header.encode("ascii")
        data = header + body
        data_written = 0
        try:
            while data_written < len(data):
                debug(f'Written : {data[data_written:]}')
                written = writer.write(data[data_written:])

                # BytesIO.write(), and always returns None instead of the number of
                # bytes written - but also guarantees that it is always a full write.
                if written is None:
                    break
                data_written += written
            writer.flush()
        except Exception as exc:
            debug(f'error while writing : {body}')
            debug_exception()

    def empty(self):
        return self._cmd_queue.empty()

    def kill_thread(self):
        self._kill_received = True


class PollingThread(threading.Thread):
    def __init__(self, device, main_db):
        threading.Thread.__init__(self)
        self.main_db = main_db
        self.device = device
        self.setName("PollingThread")
        self.poll_count = 0
        self.sleep_time = 0.1
        self._kill_received = False

    def run(self):
        a = 1
        try:
            while not self._kill_received and self.device.sequencer.is_active():
                time.sleep(0.05)
                if self.main_db.debugger_api.is_in_breakpoint(self.device):
                    self.poll_count = 0
                    self.main_db.state = State.Breakpoint
                    self.main_db.command_processor._send_stopped_event(self.main_db, 'breakpoint')

                    while self.main_db.state is not State.Running:
                        pass
                    debug(f'Finished waiting for breakpoint')
                else:
                    self.poll_count += 1
                    if self.poll_count == 100:
                        self.main_db.device.regs.Config.SEQ_condition_en_reg_hi.Write(0x1)
                    if self.poll_count >= 200:
                        break
        except Exception:
            debug_exception()
        finally:
            # Finito la comedia
            self.main_db.command_processor.handle_termination_event(self.main_db, '\nProgram Finished')

    def kill_thread(self):
        self._kill_received = True


# Main debugger class
class MainDebugger:
    def __init__(self):
        self.rec_api_dll_path = None
        self.version = None
        self.vayyar_config = None
        self.db_folder_path = None
        self.prog_bin_path = None
        self.param_bin_path = None
        self.prog_txt_path = None
        self.device_to_debug = None
        self.command_processor = CommandProcessor(self._from_json)
        self.state = State.PreRun
        self.reader = None
        self.writer = None
        self._main_lock = threading.Lock()

        if sys.version_info >= (3,):
            stdin = sys.stdin.buffer
            stdout = sys.stdout.buffer
        else:
            stdin = sys.stdin
            stdout = sys.stdout
            if sys.platform == "win32":
                import msvcrt
                msvcrt.setmode(stdin.fileno(), os.O_BINARY)
                msvcrt.setmode(stdout.fileno(), os.O_BINARY)

        write_to = stdout
        read_from = stdin

        curr_reader = getattr(self, 'reader', None)
        curr_writer = getattr(self, 'writer', None)
        if curr_reader:
            curr_reader.kill_thread()
        if curr_writer:
            curr_writer.kill_thread()

        self.reader = ReaderThread(read_from, self)
        self.writer = WriterThread(write_to, self)
        self.polling_thread = None

    def run(self):
        self.reader.start()
        self.writer.start()
        time.sleep(0.1)  # give threads time to start

        self.reader.join()
        self.writer.join()

    def initialize_debugger_api(self):
        if not self.rec_api_dll_path.exists():
            self.command_processor._send_output_event(self,
                                                      f'\nFile is Missing : {self.rec_api_dll_path}\n Please '
                                                      f'install VayyarUtils first')
    
        if self.vayyar_config and not self.vayyar_config.exists():
            self.command_processor._send_output_event(self,
                                                      f'\nFile is Missing : {self.vayyar_config}\n Please install '
                                                      f'VayyarUtils first')
        if not self.db_folder_path.exists():
            self.command_processor._send_output_event(self,
                                                      f'\Folder is Missing : {self.db_folder_path}\n Please install '
                                                      f'VayyarUtils first')
        
        all_exists = self.rec_api_dll_path.exists() and self.db_folder_path.exists()
        if not all_exists:
            self.command_processor.handle_termination_event(self)
            time.sleep(5)
        else:
            msg = f'\nInitializing Debugger with :\nRecAPI:{self.rec_api_dll_path}\nDB folder:{self.db_folder_path}\nconfig:{self.vayyar_config}\nversion:{self.version}'
            self.command_processor._send_output_event(self, msg)

            try:
                self.debugger_api = DebuggerApi(self.rec_api_dll_path,self.db_folder_path,self.version,self.vayyar_config)
                self.command_processor._send_output_event(self, "\nDebugger Initialized Successfully ! ")
            except:
                msg = f'\nFailed to initialize DebuggerApi\n Exception:{traceback.format_exc()}'
                self.command_processor.handle_termination_event(self, msg)
                time.sleep(5)

    def verify_all_files_exist_and_legal(self, code_txt_file):

        self.prog_txt_path = Path(code_txt_file)
        self.parent_dir = self.prog_txt_path.parent

        self.prog_bin_path = self.parent_dir.joinpath('code.bin')
        self.param_bin_path = self.parent_dir.joinpath('param.bin')
        self.param_txt_path = self.parent_dir.joinpath('param.txt')

        if not self.prog_bin_path.exists():
            self.command_processor._send_output_event(self, f'\nFile is Missing : {self.prog_bin_path}')

        if not self.param_bin_path.exists():
            self.command_processor._send_output_event(self, f'\nFile is Missing : {self.param_bin_path}')

        if not self.param_txt_path.exists():
            self.command_processor._send_output_event(self, f'\nFile is Missing : {self.param_txt_path}')

        all_exists = self.prog_bin_path.exists() and self.param_bin_path.exists() and self.param_txt_path.exists()
        if not all_exists:
            self.command_processor.handle_termination_event(self)
            time.sleep(5)

        files_msg = f'\nDebugged Code Text: {self.prog_txt_path} \nDebugged Binary: {self.prog_bin_path}'
        self.command_processor._send_output_event(self, files_msg)

        bin_and_txt_match = self.debugger_api.pre_verification_txt_and_bin(str(self.prog_txt_path),
                                                                           str(self.prog_bin_path))
        if not bin_and_txt_match:
            msg = f'\nError ! Code Text & Binary does not match'
            self.command_processor.handle_termination_event(self, msg)
            time.sleep(5)


    def set_device_to_debug(self,device_name):        
        self.device_to_debug = device_name
        
        
        self.command_processor._send_output_event(self,f'\nDevice to debug: {device_name}')

        self.device = self.debugger_api.connect_and_get_device_if_available(device_name)

        if not self.device:
            self.command_processor._send_output_event(self,f'\nAvailable Devices : {self.debugger_api.get_available_devices()}\n')
            self.command_processor.handle_termination_event(self, f'\nFailed to connect {device_name} !')
            time.sleep(5)

    # initialization sequence of Vayyar debugger 
    def initialize_debugger(self):
        self.debugger_api.load_program_and_param(
            self.device,
            str(self.prog_bin_path),
            str(self.param_bin_path),
            prog_txt_file=str(self.prog_txt_path),
            param_txt_file=str(self.param_txt_path))

    def start_debug_prog(self):
        self.state = State.Running
        self.polling_thread = PollingThread(self.device, self)
        self.device.sequencer.run()
        time.sleep(1)
        self.polling_thread.start()

    def _from_json(self, json_msg):
        return base_schema.from_json(json_msg)


def main():
    try:
        pid = utils.get_pid()
        log.DEBUG_FLAG = False
        if log.DEBUG_FLAG:
            import debugpy
            port = 5678
            print(f"Process:{pid}, Port:{port}")
            debugpy.listen(port)
            print('waiting for client')
            debugpy.wait_for_client()
            print('client is here')
            debugpy.breakpoint()

        debug(f"main entered, Process ID : {pid} \n")
        main_db = MainDebugger()
        main_db.run()

    except:
        debug_exception()

    debug('exiting main.\n')


if __name__ == '__main__':
    main()
