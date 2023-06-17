import json
import numpy as np


class EnumValue:

    def __init__(self):
        self.valName = ""
        self.field = None

    def IsSet(self):
        return self.field.GetValue() == self.field.enumValues[self.valName]

    def Set(self):
        self.field.SetValue(self.field.enumValues[self.valName])

    @property
    def Value(self):
        return self.field.enumValues[self.valName]


class RegField:
    def __init__(self):
        self.__parent__ = None
        self.__name__ = ""
        self.description = ""
        self.bitOffset = 0
        self.bitWidth = 0
        self.defaultValue = 0
        self.enumValues = {}

    def GetField(self, pos, size):
        return np.uint64((self.__parent__.regValue >> np.uint64(pos)) & np.uint64((0xFFFFFFFFFFFFFFFF >> (64 - size))))

    def SetField(self, pos, size, value):
        # Check value is valid and fits according to the bit width of the field
        maxval = np.power(2, size) - 1
        if (value > maxval):
            raise Exception("Value [" + str(value) + "] is bigger than the max allowed size [" + str(
                maxval) + "] of field [" + self.__name__ + "] whose size in bits is [" + str(self.bitWidth) + "].")
        self.__parent__.Value = self.__parent__.Value & np.uint64(
            (~((0xFFFFFFFFFFFFFFFF >> (64 - size)) << pos))) | np.uint64(((int(value)) << pos))

    def SetValue(self, value):
        self.__parent__.Read()
        self.SetField(self.bitOffset, self.bitWidth, value)
        self.__parent__.Write()

    def GetValue(self):
        self.__parent__.Read()
        return self.GetField(self.bitOffset, self.bitWidth)

    @property
    def Value(self):
        return self.GetField(self.bitOffset, self.bitWidth)

    @Value.setter
    def Value(self, val):
        self.SetField(self.bitOffset, self.bitWidth, val)


class Reg:
    def __init__(self, chipType):
        self.chip_type = chipType
        if self.chip_type.type == 'CentipedeB':
            self.__AddressOf_RF1_data_rd__ = 308  # 308
            self.__AddressOf_RF2_data_rd__ = 4    # 0x0004
            self.__AddressOf_RF3_data_rd__ = 5    # 0x0005
            self.__AddressOf_RF4_data_rd__ = 307  # 307
        self.__name__ = ""
        self.description = ""
        self.memType = ""
        self._addr = 0
        self.offset = 0
        self.size = 0
        self.access = "RW"
        self.busID = 0

        self.fields = []
        self.regValue = np.uint64(0)
        self.device_accessor = None

    def Write(self, value=None):
        if value is not None:
            self.regValue = np.uint64(value)
        if self.memType == 'Config':
            self.device_accessor.write_mem(self.chip_type.SEQ_base_address + self._addr, self.regValue)
        elif self.memType == "RF1" or self.memType == "RF2" or self.memType == "RF3" or self.memType == "RF4":
            if self.memType == "RF1":
                self.device_accessor.write_mem(self.chip_type.RF1_base_address + self._addr, self.regValue)
            elif self.memType == "RF2":
                self.device_accessor.write_mem(self.chip_type.RF2_base_address + self._addr, self.regValue)
            elif self.memType == "RF3":
                self.device_accessor.write_mem(self.chip_type.RF3_base_address + self._addr, self.regValue)
            elif self.memType == "RF4":
                self.device_accessor.write_mem(self.chip_type.RF4_base_address + self._addr, self.regValue)
        else:
            raise Exception("Unsupported mem type while performing indirect read")

    def Read(self):
        if self.memType == 'Config':
            self.regValue = np.uint64(self.device_accessor.read_mem(self.chip_type.SEQ_base_address + self._addr))
        elif self.memType == "RF1" or self.memType == "RF2" or self.memType == "RF3" or self.memType == "RF4":
            if self.chip_type.type == 'CentipedeB':
                self.Read_CTP_B()
            elif self.chip_type.type == 'CentipedeC':
                self.Read_CTP_C()
        else:
            raise Exception("Unsupported mem type while performing indirect read")

        return self.regValue

    def Read_CTP_B(self):
        '''
        No need to read the status register. Waiting for 3 micro seconds and reading 
        the result immediately should be enough.

        For RF1 & RF2 implement indirect read
        while (MemoryManager.Instance.Config.Params["RFStatus"].Read() != 0)
        {
            System.Threading.Thread.Sleep(1);
        }
        '''
        if self.memType == "RF1":
            self.regValue = np.uint64(self.device_accessor.read_mem(self.__AddressOf_RF1_data_rd__))
        elif self.memType == "RF2":
            self.regValue = np.uint64(self.device_accessor.read_mem(self.__AddressOf_RF2_data_rd__))
        elif self.memType == "RF3":
            self.regValue = np.uint64(self.device_accessor.read_mem(self.__AddressOf_RF3_data_rd__))
        elif self.memType == "RF4":
            self.regValue = np.uint64(self.device_accessor.read_mem(self.__AddressOf_RF4_data_rd__))

    def Read_CTP_C(self):
        if self.memType == "RF1":
            self.regValue = np.uint64(self.device_accessor.read_mem(self.chip_type.RF1_base_address + self._addr))
        elif self.memType == "RF2":
            self.regValue = np.uint64(self.device_accessor.read_mem(self.chip_type.RF2_base_address + self._addr))
        elif self.memType == "RF3":
            self.regValue = np.uint64(self.device_accessor.read_mem(self.chip_type.RF3_base_address + self._addr))
        elif self.memType == "RF4":
            self.regValue = np.uint64(self.device_accessor.read_mem(self.chip_type.RF4_base_address + self._addr))

    @property
    def Value(self):
        return self.regValue

    @Value.setter
    def Value(self, val):
        self.regValue = np.uint64(val)


class RegsBlock:
    pass


class Regs:
    def __init__(self, _device_accessor, chipType):
        self.__dict__ = {}
        self.flatRegs = {}
        self.addr_to_reg = {}
        data = json.load(open(chipType.regs_path))
        for blockName, blockData in data.items():
            self.__dict__[blockName] = RegsBlock()
            self.__dict__[blockName].__dict__ = {}
            for regData in blockData:
                reg = Reg(chipType)
                reg.__name__ = regData['name']
                reg.device_accessor = _device_accessor   # TODO: Maybe call via Parent
                reg.description = regData['description'].replace('|', '\n')
                reg.memType = regData['memType']
                reg._addr = int(regData['addr'])
                reg.offset = int(regData['offset'])
                reg.size = int(regData['size'])
                reg.access = regData['access']
                reg.busID = int(regData['busID'])
                reg.doc = reg.description

                for fieldData in regData['fields']:
                    field = RegField()
                    field.__parent__ = reg
                    field.__name__ = fieldData['name']
                    field.description = fieldData['description'].replace('|', '\n')
                    field.bitOffset = int(fieldData['bitOffset'])
                    field.bitWidth = int(fieldData['bitWidth'])
                    field.defaultValue = int(fieldData['defaultValue'])
                    field.Value = field.defaultValue
                    field.enumValues = {}
                    field.doc = field.description

                    for enumData in fieldData['enumValues']:
                        for k in enumData:
                            field.enumValues[k] = enumData[k]
                            enumWrapper = EnumValue()
                            enumWrapper.field = field
                            enumWrapper.valName = k
                            field.__dict__[k] = enumWrapper

                    reg.fields.append(field)
                    reg.__dict__[field.__name__] = field

                self.__dict__[blockName].__dict__[reg.__name__] = reg
                self.flatRegs[reg.__name__] = reg
                self.addr_to_reg[reg._addr] = reg
                
    def FieldByPrefix(self, pathPrefix, fieldName):
        for k in self.flatRegs:
            if str.startswith(k, pathPrefix) and fieldName in self.flatRegs[k].__dict__:
                return self.flatRegs[k].__dict__[fieldName], self.flatRegs[k].memType
        return None, None

class Param:
    def __init__(self, name, addr, device_accessor):
        self.__name__ = name
        self._addr = addr
        self.param_value = np.uint64(0)
        self.device_accessor = device_accessor

    def Write(self, value=None):
        if value :
            self.param_value = np.uint64(value)
        self.device_accessor.write_mem(self._addr, self.param_value)

    def Read(self):
        self.param_value = np.uint64(self.device_accessor.read_mem(self._addr))
        return self.param_value

    @property
    def Value(self):
        return self.param_value

    @Value.setter
    def Value(self, val):
        self.param_value = np.uint64(val)

class RxMemReg:
    def __init__(self, name, addr, device_accessor):
        self.__name__ = name
        self._addr = addr
        self.rx_reg_value = np.uint64(0)
        self.device_accessor = device_accessor

    def Write(self, value=None):
        if value :
            self.rx_reg_value = np.uint64(value)
        self.device_accessor.write_mem(self._addr, self.rx_reg_value)

    def Read(self):
        self.rx_reg_value = np.uint64(self.device_accessor.read_mem(self._addr))
        return self.rx_reg_value

    @property
    def Value(self):
        return self.rx_reg_value

    @Value.setter
    def Value(self, val):
        self.rx_reg_value = np.uint64(val)


class Params:
    def __init__(self, _device_accessor, _param_txt_path, base_memory):
        self.__dict__ = {}
        self.base_memory = base_memory
        self.addr_to_param = {}
        with open(_param_txt_path) as f:
            param_lines = f.readlines()
        for line in param_lines:
            tabs = line.rsplit('\t')
            if len(tabs) == 4:
                param_addr = int(tabs[0],16)+base_memory
                param_name = tabs[-1][:-1]
                p = Param(param_name,param_addr,_device_accessor)
                self.addr_to_param[param_addr] = p
                self.__dict__[param_name] = p
        
        
