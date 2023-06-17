from collections import OrderedDict
from debugger.debugger_utils import DebuggerUtils, Breakpoint, StackFrame, StackFrameVariable, Func
from debugger.DeviceAccessPythonWrapper import *
import linecache
import csv
import re


class DebuggerApi:
    def __init__(self, rec_api_dll_path :Path, db_folder_path:Path, version, config_path = None):
        if config_path:
            config_path = str(config_path)
        DeviceAccessor.init(str(rec_api_dll_path) , str(db_folder_path), version, config_path)
        self.chip_type = DeviceAccessor.version_str_to_chipType(version)
        DebuggerUtils.SEQ_PARAM_MEM = self.chip_type.param_memory_base
        DebuggerUtils.RX_MEMORY = self.chip_type.rx_memory_base
        self.break_point_code_bin = self.chip_type.breakpoint_code_path
        self.breakpoint_code_start_rel_address = 0
        self.breakpoint_code_end_rel_address = 0
        self.execution_line_before_return_rel_address = 0
        self.program_bin_path = None
        self.param_bin_path = None
        self.program_code_txt_file = None
        self.program_code = None
        self.param_code = None
        self.breakpoints_dict = {}
        self.step_breakpoints_dict = {}
        self.bin_code_line_to_txt_code_line_dict = {}
        self.txt_code_line_to_bin_code_line_dict = {}
        self.addr_to_param_dict = {}
        self.addr_to_reg_dict = {}
        self.addr_to_rx_mem_reg_dict = {}
        self.funcs_dict = None
        self.funcs_first_lines = None
        self.call_stack_frames_dict = None
        self.watched_variables = {}

    def get_available_devices(self):
        return DeviceAccessor.get_available_devices()
    
    def connect_and_get_device_if_available(self, device_model):
        return DeviceAccessor.connect_and_get_device_if_available(device_model, self.chip_type)


    @staticmethod
    def pre_verification_txt_and_bin(prog_txt_file, prog_bin_file):
        try:
            with open(prog_bin_file, 'rb') as binary_file:
                bin_arr_iter = iter(bytearray(binary_file.read()))
            with open(prog_txt_file, 'r') as f:
                f_lines = f.readlines()

            for n, line in enumerate(f_lines):
                tabs = line.rsplit('\t')
                if len(tabs[0]) == 6:
                    try:
                        opcode_shorts = tabs[1].split()
                        for i in range(6):
                            b1 = int(opcode_shorts[i], 16)
                            b2 = next(bin_arr_iter)
                            if b1 != b2:
                                raise Exception('bin and txt Files are different !!')
                        # two extra shorts that are zeroes
                        next(bin_arr_iter)
                        next(bin_arr_iter)

                    except Exception as e:
                        if str(e) == 'bin and txt Files are different !!':
                            raise Exception('bin and txt Files are different !!')
                        else:
                            pass
            return True
        except Exception as e:
            return False

    # A tool for debugging the debugger - making sure the seq code that is loaded before and after the addition of breakpoints is correct.
    def save_program(self, _device, filename):
        _device.sequencer.access_memory(host=True)
        _device.sequencer.save_program(self.breakpoint_code_end_rel_address, fr"C:\Users\DorGolfaiz\Desktop\Vayyar-Dor\SequencerDebuggerOutputs\{filename}.txt")
        _device.sequencer.access_memory(host=False)

    def load_program_and_param(self, _device, program_bin_path, param_bin_path, prog_txt_file=None,
                               param_txt_file=None):
        _device.sequencer.access_memory(host=True)

        self.program_bin_path = program_bin_path
        self.param_bin_path = param_bin_path
        self.program_code_txt_file = prog_txt_file
        self.param_code_txt_file = param_txt_file
        self.program_code = DebuggerUtils.bin_file_to_shorts_list(program_bin_path)
        self.param_code = DebuggerUtils.bin_file_to_shorts_list(param_bin_path)

        if self.program_code_txt_file:
            self.verify_code_txt_and_bin()
            self.set_funcs_dict()
            self.set_funcs_args_dict(_device.regs.Config.SEQ_DST_base_addr_lo._addr)

        if self.param_code_txt_file:
            self.set_params_dict(_device)
        self.set_regs_dict(_device)

        _device.sequencer.load_program(self.program_code, path=False)
        self.breakpoint_code_start_rel_address = len(self.program_code)
        _device.sequencer.load_param(self.param_code, path=False)
        self.load_breakpoint_code(_device)

        _device.sequencer.access_memory(host=False)

    def verify_code_txt_and_bin(self):
        try:
            with open(self.program_bin_path, 'rb') as binary_file:
                bin_arr_iter = iter(bytearray(binary_file.read()))
            with open(self.program_code_txt_file, 'r') as f:
                f_lines = f.readlines()

            for n, line in enumerate(f_lines):
                tabs = line.rsplit('\t')
                if len(tabs)>=2 and len(tabs[0]) == 6:
                    try:
                        bin_code_line = int(tabs[0], base=16)

                        self.txt_code_line_to_bin_code_line_dict[n + 1] = bin_code_line
                        self.bin_code_line_to_txt_code_line_dict[bin_code_line] = n + 1

                        opcode_shorts = tabs[1].split()
                        for i in range(6):
                            b1 = int(opcode_shorts[i], 16)
                            b2 = next(bin_arr_iter)
                            if b1 != b2:
                                raise Exception('bin and txt Files are different !!')
                        # two extra shorts that are zeroes
                        next(bin_arr_iter)
                        next(bin_arr_iter)

                    except Exception as e:
                        if str(e) == 'bin and txt Files are different !!':
                            raise Exception('bin and txt Files are different !!')
                        else:
                            pass

        except Exception as e:
            raise Exception(f"Failed to verify txt vs bin , reason : {e}")

    def load_breakpoint_code(self, _device):
        breakpoint_code_size = os.stat(self.break_point_code_bin).st_size // 2
        # loading breakpoint code
        _device.sequencer.load_program(self.break_point_code_bin, address_shift=self.breakpoint_code_start_rel_address)
        self.breakpoint_code_end_rel_address = self.breakpoint_code_start_rel_address + breakpoint_code_size
        self.execution_line_before_return_rel_address = self.breakpoint_code_end_rel_address - 8

    def release_breakpoint(self, _device, execute_last_line=True):

        if execute_last_line:
            _device.sequencer.access_memory(host=True)
            opcode = self.get_code_line_to_execute(_device)

            self.edit_execution_line_before_return(_device, opcode)

        _device.sequencer.access_memory(host=False)
        _device.regs.Config.PERI_handshake_write.Write(0x302)

    def convert_txt_code_line_to_bin_code_line(self, line_num):
        line = linecache.getline(self.program_code_txt_file, line_num)
        bin_code_line = None
        first_tab = line.rsplit('\t')[0]
        if len(first_tab) == 6:
            try:
                bin_code_line = int(first_tab, base=16)
            except:
                bin_code_line = None
        self.bin_code_line_to_txt_code_line_dict[bin_code_line] = line_num
        return bin_code_line

    @staticmethod
    def is_in_breakpoint(_device):
        if _device.regs.Config.PERI_handshake_read.Read() == 1:
            return True
        return False

    @staticmethod
    def is_addr_in_config_memory(_device, addr):
        if 0 <= addr < _device.chip_type.param_memory_base:
            return True
        else:
            return False

    @staticmethod
    def is_addr_in_param_memory(_device, addr):
        if _device.chip_type.param_memory_base <= addr:
            return True
        else:
            return False

    @staticmethod
    def is_addr_in_rx_memory(_device, addr):
        if _device.chip_type.rx_memory_base <= addr < _device.chip_type.param_memory_base:
            return True
        else:
            return False

    def insert_breakpoint(self, _device, code_line_num, code_line_relates_to_code_txt=False, step_breakpoint=False):
        # if the code line relates to the txt file - we should convert it to bin code line first 
        if code_line_relates_to_code_txt:
            code_line_num = self.txt_code_line_to_bin_code_line_dict.get(code_line_num)

        if code_line_num:
            try:
                original_opcode = self.program_code[code_line_num * 4:(code_line_num * 4) + 4]
                original_opcode = DebuggerUtils.get_u_shorts_array_from_list(original_opcode)
                if not DebuggerUtils.is_breakpoint_legal_on_opcode(original_opcode):
                    return False
                else:
                    b = Breakpoint(code_line_num, original_opcode)
                    if step_breakpoint:
                        self.step_breakpoints_dict[b.code_bin_line] = b
                    else:
                        self.breakpoints_dict[b.code_bin_line] = b

                    jump_to_breakpoint_opcode = DebuggerUtils.get_jump_opcode(
                        self.breakpoint_code_start_rel_address // 4, push_curr_address=True)
                    _device.sequencer.access_memory(host=True)
                    _device.sequencer.load_program(jump_to_breakpoint_opcode, path=False,
                                                   address_shift=(code_line_num * 4))
                    _device.sequencer.access_memory(host=False)
                    return True
            except:
                return False
        return False

    def remove_all_breakpoints(self, _device):
        d_keys = list(self.breakpoints_dict.keys())
        for code_line_num in d_keys:
            self.remove_breakpoint(_device, code_line_num)

    def remove_all_stepping_breakpoints(self, _device):
        d_keys = list(self.step_breakpoints_dict.keys())
        for code_line_num in d_keys:
            if code_line_num in self.breakpoints_dict:
                continue
            else:
                self.remove_breakpoint(_device, code_line_num, step_breakpoint=True)

    def remove_breakpoint(self, _device, code_line_num, code_line_relates_to_code_txt=False, step_breakpoint=False):

        if code_line_relates_to_code_txt:
            code_line_num = self.convert_txt_code_line_to_bin_code_line(code_line_num)

        if code_line_num:
            if step_breakpoint:
                b = self.step_breakpoints_dict.get(code_line_num)
            else:
                b = self.breakpoints_dict.get(code_line_num)
            if b:
                original_opcode = b.original_opcode
                _device.sequencer.access_memory(host=True)
                _device.sequencer.load_program(original_opcode, path=False, address_shift=(code_line_num * 4))
                _device.sequencer.access_memory(host=False)
                if step_breakpoint:
                    del self.step_breakpoints_dict[code_line_num]
                else:
                    del self.breakpoints_dict[code_line_num]
            else:
                raise Exception(f'Breakpoint cannot be removed because it does not exist')

    def edit_execution_line_before_return(self, _device, opcode):
        _device.sequencer.load_program(opcode, path=False, address_shift=self.execution_line_before_return_rel_address)

    @staticmethod
    def get_call_stack_ptr(_device):
        ptr = _device.regs.Config.SEQ_stack_ptr.Read()
        return int(ptr)

    @staticmethod
    def get_pc(_device):
        pc = _device.regs.Config.SEQ_prog_counter.Read()
        return int(pc)

    @staticmethod
    def get_call_stack(_device):
        stack = []
        stack_address = _device.regs.Config.SEQ_stack_addr0._addr
        stack_ptr = DebuggerApi.get_call_stack_ptr(_device)
        for i in range(stack_ptr):
            stack.append(_device.read_mem(stack_address + i))
        return stack

    def get_stack_frames(self, _device):
        call_stack = []
        stack = self.get_clean_call_stack(_device)[::-1]
        for pc in stack:
            if pc != 0:
                line = pc - 1
                txt_code_line = self.bin_code_line_to_txt_code_line_dict.get(line)
                # if None - This means the line fe
                func_line = self.get_closest_func(line)
                func_obj = self.funcs_dict[func_line]
                frame = StackFrame(line, txt_code_line, func_obj)
                call_stack.append(frame)
        self.set_call_stack_frames_dict(call_stack)
        return call_stack

    def get_clean_call_stack(self, _device):
        num_opcodes = len(self.program_code) // 4
        call_stack = DebuggerApi.get_call_stack(_device)
        clean_call_stack = [s for s in call_stack if s < num_opcodes]
        return clean_call_stack

    def get_code_line_to_execute(self, _device):
        call_stack = self.get_call_stack(_device)

        # in order to execute the line before
        code_line_num = call_stack[-1] - 1

        opcode = self.program_code[code_line_num * 4:(code_line_num * 4) + 4]
        opcode = DebuggerUtils.get_u_shorts_array_from_list(opcode)
        o = self.breakpoints_dict.get(code_line_num)
        if o:
            o = o.original_opcode
        else:
            a = 1

        return opcode

    def get_opcode_by_code_line(self, code_line_num):
        opcode = self.program_code[code_line_num * 4:(code_line_num * 4) + 4]
        opcode = DebuggerUtils.get_u_shorts_array_from_list(opcode)
        return opcode

    def set_funcs_dict(self):
        if self.program_code_txt_file:
            FUNC_FORMAT = {
                re.escape('class passable_ptr<class ILFunction> __cdecl'): '',
                re.escape('Vayyar::Centipede::'): ''}
            rows = [row for row in csv.reader(open(self.program_code_txt_file), skipinitialspace=True)]
            funcs = OrderedDict()
            for i in range(len(rows)):
                if rows[i] and not rows[i][0].startswith('00') and not rows[i][0].startswith('\t\t#'):  # new func
                    pc = int(rows[i + 1][0].split()[0], 16)
                    # apply FUNC_FORMATs to the given func name
                    func_name = re.compile('|'.join(FUNC_FORMAT.keys())).sub(
                        lambda m: FUNC_FORMAT[re.escape(m.group(0))], ' '.join(rows[i]))
                    # also remove everything inside parentheses
                    func_name = re.sub(r'\(.*\)', '()', func_name.replace('(*)', '()'))
                    funcs[pc] = Func(pc, func_name)
            self.funcs_dict = funcs

    def set_funcs_args_dict(self, seq_dst_base_addr_lo):

        if self.program_code_txt_file:
            if self.funcs_first_lines is None:
                self.funcs_first_lines = list(self.funcs_dict.keys())

            for i in range(len(self.funcs_first_lines)):
                start_line = self.funcs_first_lines[i]
                func_obj = self.funcs_dict[start_line]
                txt_start_line = self.bin_code_line_to_txt_code_line_dict[start_line]

                if i == len(self.funcs_first_lines) - 1:
                    bin_end_line = (len(self.program_code) // 4) - 1
                else:
                    bin_end_line = self.funcs_first_lines[i + 1]

                txt_end_line = self.bin_code_line_to_txt_code_line_dict[bin_end_line]
                func_obj.set_additional_data(bin_end_line, txt_start_line, txt_end_line)
                args_addresses_d = OrderedDict()
                for n in range(start_line, bin_end_line):
                    opcode = self.get_opcode_by_code_line(n)
                    if DebuggerUtils.op_is_copy(opcode) or DebuggerUtils.op_is_write(opcode):
                        dest = DebuggerUtils.get_dest_addr_from_copy_or_write(opcode)
                        if DebuggerUtils.op_is_add_base_to_dest_copy(
                                opcode) or DebuggerUtils.op_is_add_base_to_dest_write(opcode):
                            base_addr = self.get_closest_dest_base_addr(n, seq_dst_base_addr_lo)
                            dest += base_addr

                        args_addresses_d[dest] = None
                args_addrs = list(args_addresses_d.keys())
                func_obj.set_additional_data(args_addresses=args_addrs)

    def get_closest_dest_base_addr(self, bin_code_line, seq_dst_base_addr_lo):
        prev_code_line = bin_code_line - 1
        prev_op = self.get_opcode_by_code_line(prev_code_line)
        c = DebuggerUtils.op_is_write(prev_op) and (
                    DebuggerUtils.get_dest_addr_from_copy_or_write(prev_op) == seq_dst_base_addr_lo)
        while not c:
            prev_code_line -= 1
            prev_op = self.get_opcode_by_code_line(prev_code_line)
            c = DebuggerUtils.op_is_write(prev_op) and (
                        DebuggerUtils.get_dest_addr_from_copy_or_write(prev_op) == seq_dst_base_addr_lo)
            if prev_code_line == 0:
                return 0
        v = DebuggerUtils.get_data_from_write(prev_op)
        return v

    def set_params_dict(self, _device):
        _device.set_params(self.param_code_txt_file)
        self.addr_to_param_dict = _device.params.addr_to_param

    def create_param(self, _device, addr, name=''):
        new_p = _device.create_new_param(addr, name)
        self.addr_to_param_dict[addr] = new_p

    def create_rx_mem_reg(self, _device, addr, name=''):
        new_p = _device.create_new_rx_mem_reg(addr, name)
        self.addr_to_rx_mem_reg_dict[addr] = new_p

    def set_regs_dict(self, _device):
        self.addr_to_reg_dict = _device.regs.addr_to_reg

    def get_closest_func(self, bin_code_line):
        if self.funcs_dict:
            if self.funcs_first_lines is None:
                self.funcs_first_lines = list(self.funcs_dict.keys())

            low = 0
            high = len(self.funcs_first_lines) - 1
            middle = (low + high) // 2
            while low <= high:
                val = self.funcs_first_lines[middle]
                if val == bin_code_line:
                    return bin_code_line
                elif val > bin_code_line:
                    high = middle - 1
                else:
                    low = middle + 1

                middle = (low + high) // 2
        return self.funcs_first_lines[low - 1]

    def step(self, _device, step_type='next'):
        if self.is_in_breakpoint(_device):
            self.remove_all_stepping_breakpoints(_device)

            clean_call_stack = self.get_clean_call_stack(_device)
            opcode = self.get_opcode_by_code_line(clean_call_stack[-1] - 1)
            opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
            opcode_is_return = DebuggerUtils.op_is_return(opcode)
            opcode_is_branch = DebuggerUtils.op_is_branch(opcode)
            opcode_is_conditional_branch = DebuggerUtils.op_is_cond_branch(opcode)
            op_is_jump = DebuggerUtils.op_is_jump(opcode)

            to_code_line = 0
            if step_type == 'in':
                if opcode_is_branch and not opcode_is_conditional_branch:
                    to_code_line = DebuggerUtils.select_bits_from_num(opcode_as_num, 4, 20)
                else:
                    step_type = 'next'

            elif step_type == 'out':
                to_code_line = clean_call_stack[-2]

            if step_type == 'next':
                if opcode_is_return:
                    # like stepping out
                    to_code_line = clean_call_stack[-2]
                elif opcode_is_conditional_branch:
                    to_code_line = DebuggerUtils.select_bits_from_num(opcode_as_num, 4, 20)
                else:
                    to_code_line = clean_call_stack[-1]

            to_code_line = self.get_next_valid_step_location(to_code_line, clean_call_stack)
            self.insert_breakpoint(_device, to_code_line, step_breakpoint=True)

            if opcode_is_conditional_branch and step_type != 'out':  # in this case we need to put another breakpoint (if & else)
                to_code_line_2 = clean_call_stack[-1]
                to_code_line_2 = self.get_next_valid_step_location(to_code_line_2, clean_call_stack)
                self.insert_breakpoint(_device, to_code_line_2, step_breakpoint=True)

            self.release_breakpoint(_device)

    def set_call_stack_frames_dict(self, call_stack):
        self.call_stack_frames_dict = OrderedDict()
        for frame in call_stack:
            self.call_stack_frames_dict[frame.bin_code_line] = frame

    def get_next_valid_step_location(self, to_code_line, clean_call_stack):

        opcode = self.get_opcode_by_code_line(to_code_line)
        i = 2
        while (DebuggerUtils.is_breakpoint_legal_on_opcode(opcode) is False) and i <= len(clean_call_stack):
            if DebuggerUtils.op_is_jump(opcode) and not DebuggerUtils.op_is_return(opcode) :
                opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
                jump_destination = DebuggerUtils.select_bits_from_num(opcode_as_num, 4, 20)

                if DebuggerUtils.is_breakpoint_legal_on_opcode(self.get_opcode_by_code_line(jump_destination)):
                    to_code_line = jump_destination
                else:
                    to_code_line = clean_call_stack[-i]

            else:
                to_code_line = clean_call_stack[-i]

            opcode = self.get_opcode_by_code_line(to_code_line)
            i += 1
        return to_code_line

    def get_stack_frame_variable_obj(self, addr, _device):
        if self.is_addr_in_config_memory(_device, addr):
            obj = self.addr_to_reg_dict.get(addr)
            name = f'[0:{hex(addr)}]'
            obj_id = id(obj)

        elif self.is_addr_in_param_memory(_device, addr):
            obj = self.addr_to_param_dict.get(addr)
            if obj is None:
                self.create_param(_device, addr)
                obj = self.addr_to_param_dict.get(addr)
                obj.__name__ = f'Param_{addr}'

            name = f'[1:{hex(addr - _device.chip_type.param_memory_base)}]'
            obj_id = id(obj)
        else:  # RxMemReg
            obj = self.addr_to_rx_mem_reg_dict.get(addr)
            if obj is None:
                self.create_rx_mem_reg(_device, addr)
                obj = self.addr_to_rx_mem_reg_dict.get(addr)
                obj.__name__ = f'Rx_Mem_{addr}'

            name = f'[2:{hex(addr - _device.chip_type.rx_memory_base)}]'
            obj_id = id(obj)

        v = StackFrameVariable(obj_id, name, addr, obj)
        return v

    def get_stack_frame_variables(self, _device, variables_id):

        bin_line = self.txt_code_line_to_bin_code_line_dict.get(variables_id)
        frame = self.call_stack_frames_dict.get(bin_line)

        # The variables id reflect a frame -> group of variables
        if frame is not None:
            addresses = frame.func_scope_obj.args_addresses
            variables = []
            for addr in addresses:
                v = self.get_stack_frame_variable_obj(addr, _device)
                variables.append(v)

            self.call_stack_frames_dict.get(bin_line).variables = variables
            return variables

        # The variables id reflect the pythonic id of the Reg/Param obj 
        else:
            py_id = variables_id
            obj = DebuggerUtils.get_py_obj_by_id(py_id)
            return obj

    def get_watched_variable(self, _device, variable_addr_str):
        try:
            addr = DebuggerUtils.get_abs_addr_from_str(variable_addr_str)
            v = self.get_stack_frame_variable_obj(addr, _device)
            self.watched_variables[addr] = v
            return v
        except:
            return None

    def read_memory_repl(self, _device, addr_str):

        try:
            addr = DebuggerUtils.get_abs_addr_from_str(addr_str)
            _device.sequencer.access_memory(host=True)
            result = _device.read_mem(addr)
            _device.sequencer.access_memory(host=False)
        except:
            result = 'Memory Read Failed'

        return result

    def write_memory_repl(self, _device, addr_str, new_val):
        try:
            addr = DebuggerUtils.get_abs_addr_from_str(addr_str)
            _device.sequencer.access_memory(host=True)
            _device.write_mem(addr, int(new_val))
            _device.sequencer.access_memory(host=False)
            result = new_val
        except:
            result = 'Memory Write Failed'
        return result

    def stop_debugging(self, _device):
        _device.sequencer.abort()
        _device.sequencer.disable()
        DeviceAccessor.shutdown()

    @staticmethod
    def obj_is_Param(obj):
        return isinstance(obj, RegsLoader.Param)

    @staticmethod
    def obj_is_RxMemReg(obj):
        return isinstance(obj, RegsLoader.RxMemReg)

    @staticmethod
    def obj_is_Reg(obj):
        return isinstance(obj, RegsLoader.Reg)

    @staticmethod
    def obj_is_RegField_list(obj):
        result = True
        if isinstance(obj, list):
            for f in obj:
                if not DebuggerApi.obj_is_RegField(f):
                    result = False
                    break
        else:
            result = False
        return result

    @staticmethod
    def obj_is_RegField(obj):
        return isinstance(obj, RegsLoader.RegField)

    @staticmethod
    def obj_is_StackFrameVariable_list(obj):
        result = True
        if isinstance(obj, list):
            for f in obj:
                if not isinstance(f, StackFrameVariable):
                    result = False
                    break
        else:
            result = False
        return result
