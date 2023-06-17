from pathlib import Path
from sre_constants import FAILURE
import json

CTP_B = 'b'
CTP_C = 'c'
centipedes = [CTP_B,CTP_C]
genRegJsonPath = Path(__file__).parents[2].joinpath(r"resources")
outputPath = Path(__file__).parents[2].joinpath(r"debugger\resources")

def main():
    RegDict_b = {'Config':[],"RF1":[],"RF2":[],"RF3":[],"RF4":[]}
    RegDict_c = {'Config':[],"RF1":[],"RF2":[],"RF3":[],"RF4":[]}

    with open (genRegJsonPath.joinpath("ConfigRegs.json"),'r') as regFile:
        cfgData = json.load(regFile)
    with open (genRegJsonPath.joinpath("RfRegs.json"),'r') as regFile:
        rfData = json.load(regFile)
    
    cfgDict = {CTP_B : RegDict_b['Config'], CTP_C : RegDict_c['Config']}
    for block in cfgData:
        for reg in block['registers']:
            for ver in centipedes:
                if reg[f'centipede_{ver}'] == True:
                    cfgDict[ver].append(create_reg_dict(reg,ver, False))
    
    rfDict = {CTP_B : {'RF1':RegDict_b['RF1'], 'RF2':RegDict_b['RF2'], 'RF3':RegDict_b['RF3'], 'RF4':RegDict_b['RF4']}, CTP_C : {'RF1':RegDict_c['RF1'], 'RF2':RegDict_c['RF2'], 'RF3':RegDict_c['RF3'], 'RF4':RegDict_c['RF4']}}
    for block in rfData:
        for reg in block['registers']:
            for ver in centipedes:
                if reg[f'centipede_{ver}'] == True:
                    if reg['super_class'] not in rfDict[ver].keys():
                        reg['super_class'] = 'RF1'
                    rfDict[ver][reg['super_class']].append(create_reg_dict(reg,ver, True))

    with open(outputPath.joinpath('centipede_B_Regs.json'),'w') as regFile:
        json.dump(RegDict_b, regFile)

    with open(outputPath.joinpath('centipede_C_Regs.json'),'w') as regFile:
        json.dump(RegDict_c, regFile)

def create_enum_values_dict(value):
    return {value['name']:value['value']}

def create_field_dict(field, ver):
    fieldDict = {}
    fieldDict['name'] = field['name']
    fieldDict['description'] = field['description']
    fieldDict['bitOffset'] = field['bit_offset']
    fieldDict['bitWidth'] = field['bit_width']
    fieldDict['defaultValue'] = int(field['default_value'],16) if type(field['default_value']) == int else 0
    fieldDict['enumValues'] = [create_enum_values_dict(value) for value in field['values'] if type(value) is not str]
    return fieldDict

def create_reg_dict(reg, ver, is_rf_reg):
    regDict = {}
    regDict['name'] = reg['name']
    regDict['addr'] = int(reg[f"address_{ver}"],16)
    regDict['access'] = reg['access']
    regDict['description'] = reg['description']
    regDict['busID'] = -1 if reg['bus_id'] == 'err' else reg['bus_id']
    if is_rf_reg:
        regDict['memType'] = reg['super_class']
    else:
        regDict['memType'] = 'Config'
    regDict['offset'] = int(reg['address_offset'],16)
    regDict['size'] = int(reg['size'])/8 if not (reg['size'] == 'TBD') else 2
    regDict['fields'] = [create_field_dict(field, ver) for field in reg['fields'] if field[f'centipede_{ver}']=='true']
    return regDict

 
if __name__ == '__main__':
    main()