from debugger.common.RegsLoader import Param, RxMemReg
import os
from pathlib import Path
import ctypes as ct
from struct import unpack
from debugger.common import RegsLoader
from debugger import resources
import PyRecordingAPI.RecAPI.RecordingAPI as RecAPI

# TODO : Read these values from json file - and then separate Sequencer Wrapper
seq_ctrl_address = 0x3000  # In order to run the sequencer - Write  0x1

class CentipedeB:
    type = 'CentipedeB'
    id = 0x7201
    param_memory_base = 0x080000
    program_memory_base = 0x040000
    SEQ_base_address = 0x0
    RF1_base_address = 0x0
    RF2_base_address = 0x0
    RF3_base_address = 0x0
    RF4_base_address = 0x0
    rx_memory_base = 0xE0000
    regs_path = resources.centipede_b_regs_file
    breakpoint_code_path = resources.centipede_b_breakpoint_code_file

class CentipedeC:
    type = 'CentipedeC'
    id = 0x7203
    param_memory_base = 0x30020000
    program_memory_base = 0x30000000
    SEQ_base_address = 0x2C800000
    RF1_base_address = 0x2C7FF000
    RF2_base_address = 0x0
    RF3_base_address = 0x2C800000
    RF4_base_address = 0x2C800000
    rx_memory_base = 0xE0000
    regs_path = resources.centipede_c_regs_file
    breakpoint_code_path = resources.centipede_c_breakpoint_code_file

class Octopus:
    type = 'Octopus'
    id = 0x2401
    param_memory_base = 0x080000
    program_memory_base = 0x040000
    rx_memory_base = 0xE0000
    regs_path = resources.octopus_regs_file

class Sequencer:
    def __init__(self, regs, chip_type):
        self.SEQRegs = regs.Config      
        self.chip_type = chip_type

    @staticmethod
    def bin_file_to_shorts_list(bin_file_path):
        with open(bin_file_path, 'rb') as binary_file:
            arr = bytearray(binary_file.read())
            file_length_in_shorts = (len(arr) // 2)
            data = (ct.c_ushort * file_length_in_shorts)()
            ushorts_list = list(unpack('H' * file_length_in_shorts, arr))
            # for i in range(file_length_in_shorts):
            #     data[i] = ct.c_ushort(tuple_of_ushorts[i])
            return ushorts_list

    def load_program(self, program_bin, path=True, address_shift=0):
        if path:
            program = Sequencer.bin_file_to_shorts_list(program_bin)
        else:
            program = program_bin
        DeviceAccessor.write_mem_dma(self.chip_type.program_memory_base + address_shift, program)

    def save_program(self, size, output):
        prog = DeviceAccessor.read_mem_dma(self.chip_type.program_memory_base, size)
        with open (output, 'w') as f:
            f.writelines("\n".join([hex(op) for op in prog]))

    def load_param(self, param_bin, path=True, address_shift=0):
        if path:
            param = Sequencer.bin_file_to_shorts_list(param_bin)
        else:
            param = param_bin

        DeviceAccessor.write_mem_dma(self.chip_type.param_memory_base + address_shift, param)

    def access_memory(self, host=True):
        DeviceAccessor.access_memory(host)

    def run(self):
        if self.is_active():
            raise Exception("Can't run program while sequencer is active")
        ###SEQUENCER RUN FLOW###
        #Seq Clear.
        self.abort()
        #Seq Condition registers.
        DeviceAccessor.write_mem(self.chip_type.SEQ_base_address + self.SEQRegs.SEQ_condition_en_reg_hi._addr, 0xffff)
        DeviceAccessor.write_mem(self.chip_type.SEQ_base_address + self.SEQRegs.SEQ_condition_en_reg_lo._addr, 0xffff)
        DeviceAccessor.write_mem(self.chip_type.SEQ_base_address + self.SEQRegs.SEQ_condition_inv_reg_hi._addr, 0x1)
        #Running the sequencer (by setting Seq_Ctrl to disable -> enable).
        #Disabling seq.
        self.disable()
        #Resetting PC to 0.
        DeviceAccessor.write_mem(self.chip_type.SEQ_base_address + self.SEQRegs.SEQ_prog_counter._addr, 0x0)
        #Enabling seq.
        self.enable()

    def is_active(self):
        status = DeviceAccessor.read_mem(self.chip_type.SEQ_base_address + self.SEQRegs.SEQ_status._addr)
        is_active = status % 2 == 1
        return is_active

    def disable(self):
        if self.is_active():
            raise Exception("Can't run program while sequencer is active")
        # enable = 0 ; seq_mem_ctrl = 1;
        DeviceAccessor.write_mem(self.chip_type.SEQ_base_address + self.SEQRegs.Seq_ctrl._addr, 0b10)

    def enable(self):
        # enable = 1 ; seq_mem_ctrl = 1;
        DeviceAccessor.write_mem(self.chip_type.SEQ_base_address + self.SEQRegs.Seq_ctrl._addr, 0b11)

    def abort(self):
        DeviceAccessor.write_mem(self.chip_type.SEQ_base_address + self.SEQRegs.SEQ_clear._addr, 0xffff)
        DeviceAccessor.write_mem(self.chip_type.SEQ_base_address + self.SEQRegs.SEQ_clear._addr, 0x0000)


class Device:
    def __init__(self, _device_id,_device_model, chip_type):
        self.device_id = _device_id
        self.device_model = _device_model
        self.chip_type = chip_type
        self.regs = RegsLoader.Regs(DeviceAccessor, self.chip_type)
        self.sequencer = Sequencer(self.regs, self.chip_type)
        self.params = None
    
    def connect(self):
        DeviceAccessor.connect(self.device_id)
    
    def set_params(self, _params_txt_file):
        self.params = RegsLoader.Params(DeviceAccessor, _params_txt_file, self.chip_type.param_memory_base)

    def create_new_param(self, addr, name=''):
        return Param(name,addr,DeviceAccessor)
    
    def create_new_rx_mem_reg(self, addr, name=''):
        return RxMemReg(name,addr,DeviceAccessor)

    def write_mem(self, address: int, data: int):
        DeviceAccessor.write_mem(self.chip_type.SEQ_base_address + address, data)

    def write_mem_dma(self, address: int, data_arr):
        DeviceAccessor.write_mem_dma(self.chip_type.SEQ_base_address + address, data_arr)

    def read_mem(self, address: int):
        return DeviceAccessor.read_mem(self.chip_type.SEQ_base_address + address)

    def read_param_mem(self, rel_address: int):
        return DeviceAccessor.read_mem(self.chip_type.param_memory_base + rel_address)

    def read_program_mem(self, rel_address: int):
        return DeviceAccessor.read_mem(self.chip_type.program_memory_base + rel_address)

    def read_mem_dma(self, address: int, size: int):
        return DeviceAccessor.read_mem_dma(self.chip_type.SEQ_base_address + address, size)


# Static class
class DeviceAccessor:
    
    chipType = None

    @staticmethod
    def init(rec_api_dll_path , db_folder_path, version, config_path = None):
        RecAPI.pre_init(rec_api_dll_path, db_folder_path, config_path)
        RecAPI.shutdown()
        RecAPI.init()
        DeviceAccessor.chipType = DeviceAccessor.version_str_to_chipType(version)

    @staticmethod
    def connect_and_get_device_if_available(device_model, chip_type):
        all_instruments = RecAPI.get_all_instrument_list()
        
        for inst in all_instruments:
            if inst.model == device_model:
                try:
                    DeviceAccessor.connect(inst.model)
                    DeviceAccessor.access_memory(host=True)
                    d = Device(inst.uid,inst.model, chip_type)
                    DeviceAccessor.access_memory(host=False)
                    return d
                except Exception as e:
                    return None
        
        return None
            
    @staticmethod
    def get_available_devices():
        all_instruments = RecAPI.get_all_instrument_list()
        available_devices = [inst.model for inst in all_instruments]
        return available_devices

    @staticmethod
    def connect(device_id):
        RecAPI.connect_to_instrument(device_id)

    @staticmethod
    def write_mem(address, data):
        RecAPI.mem_write(0,address,data)

    @staticmethod
    def write_mem_dma(address, data_arr):
        RecAPI.mem_write_dma(0, address, data_arr)
        
    @staticmethod
    def read_mem(address):
        return RecAPI.mem_read(0, address)

    @staticmethod
    def read_mem_dma(address, size):
        return RecAPI.mem_read_dma(0,address,size)

    @staticmethod
    def access_memory(host=True):
        seq_ctrl = DeviceAccessor.read_mem(DeviceAccessor.chipType.SEQ_base_address + seq_ctrl_address)

        # enable = 0 ; seq_mem_ctrl = 0(host control);
        prev_enable_bit = seq_ctrl & 0x1
        if host:
            seq_ctrl = ((seq_ctrl >> 2) << 2) | prev_enable_bit
        else:
            seq_ctrl = ((seq_ctrl >> 2) << 2) | 2 | prev_enable_bit
        DeviceAccessor.write_mem(DeviceAccessor.chipType.SEQ_base_address + seq_ctrl_address, seq_ctrl)

    @staticmethod
    def version_str_to_chipType(str):
        str_to_chipType_dict = {'Octopus':Octopus, 'CentipedeB':CentipedeB , 'CentipedeC':CentipedeC}
        return str_to_chipType_dict[str]

    @staticmethod
    def shutdown():
        RecAPI.shutdown()
