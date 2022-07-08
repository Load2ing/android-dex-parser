import libs.Dalvik_Bytecode
from libs import CustomExceptions
from libs import logger
from libs import skipclass_list

import struct
import time
import zipfile
import sys


logger.set_DA_LoggerLevel("INFO")
log = logger.DA_log


class DexAnalyzer:

    def __init__(self, input_skip_level):
        self.hdr = {}
        self.dex = None
        self.strings = []
        self.type_list = []
        self.proto_list = []
        self.field_list = []
        self.method_list = []
        self.class_list = []
        self.skip_level = input_skip_level
        self.skip_list = []
        self.targetApkPath = ""
        self.last_offset = 0

        self.string_count = 0
        self.type_count = 0
        self.proto_count = 0
        self.field_count = 0
        self.method_count = 0
        self.class_count = 0

        self.static_fields = 0
        self.instance_fields = 0
        self.direct_methods = 0
        self.virtual_methods = 0

        self.class_data_list = {}
        self.skip_string_list_small = skipclass_list.SMALL
        self.skip_string_list_full = skipclass_list.FULL

        self.filtered_method_list = []

    def setDex_Apk(self, input_apkpath):
        self.targetApkPath = input_apkpath

        zip1 = zipfile.ZipFile(input_apkpath, mode='r')
        self.dex = zip1.read("classes.dex")

    def setDex(self, dex_path):
        fp = open(dex_path, "rb")
        self.dex = fp.read()
        fp.close()

    def analyze(self):
        analyze_start_time = time.time()
        # DEX파일 유효성 검사
        if self._isDexNull():               raise CustomExceptions.DexIsEmpty()
        if not self._isValidDex():          raise CustomExceptions.DexHeaderError()

        # 중요 클래스만 빠르게 보고싶을 경우 사용하는 변수. 셋팅되어 있지 않을 경우 에러발생
        if not self._isValidSkipLevel():    raise CustomExceptions.SkipLevelError()

        self._set_skip_level()

        # dex 파싱 시작
        self._parse_dex_header()
        self._parse_dex_string()
        self._parse_type_id()
        self._parse_proto_id()
        self._parse_field_id()
        self._parse_method_id()
        self._parse_class_def()
        self._parse_class_bytecode()
        # dex 파싱 완료.

        self.show_string_list()
        self.show_type_list()
        self.show_method_list()
        self.show_field_list()
        self.show_header_data()

        analyze_end_time = time.time()

        log.info("end_time : %.4f, Last Offset :%08x" % ((analyze_end_time-analyze_start_time), self.last_offset))

    def _parse_dex_header(self):
        magic = self.dex[0x0:0x8]
        checksum        = struct.unpack("<L", self.dex[0x8:0xC])[0]
        sa1             = self.dex[0xC:0x20]
        file_size       = struct.unpack("<L", self.dex[0x20:0x24])[0]
        header_size     = struct.unpack("<L", self.dex[0x24:0x28])[0]
        endian_tag      = struct.unpack("<L", self.dex[0x28:0x2C])[0]
        link_size       = struct.unpack("<L", self.dex[0x2C:0x30])[0]
        link_off        = struct.unpack("<L", self.dex[0x30:0x34])[0]
        map_off         = struct.unpack("<L", self.dex[0x34:0x38])[0]
        string_ids_size = struct.unpack("<L", self.dex[0x38:0x3C])[0]
        string_ids_off  = struct.unpack("<L", self.dex[0x3C:0x40])[0]
        type_ids_size   = struct.unpack("<L", self.dex[0x40:0x44])[0]
        type_ids_off    = struct.unpack("<L", self.dex[0x44:0x48])[0]
        proto_ids_size  = struct.unpack("<L", self.dex[0x48:0x4C])[0]
        proto_ids_off   = struct.unpack("<L", self.dex[0x4C:0x50])[0]
        field_ids_size  = struct.unpack("<L", self.dex[0x50:0x54])[0]
        field_ids_off   = struct.unpack('<L', self.dex[0x54:0x58])[0]
        method_ids_size = struct.unpack('<L', self.dex[0x58:0x5C])[0]
        method_ids_off  = struct.unpack('<L', self.dex[0x5C:0x60])[0]
        class_defs_size = struct.unpack('<L', self.dex[0x60:0x64])[0]
        class_defs_off  = struct.unpack('<L', self.dex[0x64:0x68])[0]
        data_size       = struct.unpack('<L', self.dex[0x68:0x6C])[0]
        data_off        = struct.unpack('<L', self.dex[0x6C:0x70])[0]

        if len(self.dex) != file_size:
            raise CustomExceptions.DexSizeMismatch()

        self.hdr['magic' ]           = magic
        self.hdr['checksum' ]        = checksum
        self.hdr['sa1' ]             = sa1
        self.hdr['file_size' ]       = file_size
        self.hdr['header_size' ]     = header_size
        self.hdr['endian_tag' ]      = endian_tag
        self.hdr['link_size' ]       = link_size
        self.hdr['link_off' ]        = link_off
        self.hdr['map_off' ]         = map_off
        self.hdr['string_ids_size']  = string_ids_size
        self.hdr['string_ids_off' ]  = string_ids_off
        self.hdr['type_ids_size' ]   = type_ids_size
        self.hdr['type_ids_off' ]    = type_ids_off
        self.hdr['proto_ids_size' ]  = proto_ids_size
        self.hdr['proto_ids_off' ]   = proto_ids_off
        self.hdr['field_ids_size' ]  = field_ids_size
        self.hdr['field_ids_off' ]   = field_ids_off
        self.hdr['method_ids_size']  = method_ids_size
        self.hdr['method_ids_off' ]  = method_ids_off
        self.hdr['class_defs_size']  = class_defs_size
        self.hdr['class_defs_off' ]  = class_defs_off
        self.hdr['data_size' ]       = data_size
        self.hdr['data_off' ]        = data_off

        # TODO : map_offset 부분의 데이터를 처리하는 함수가 없음. 추가해야함.

    def _parse_dex_string(self):
        string_size = self.hdr.get("string_ids_size")
        str_ids_off = self.hdr.get("string_ids_off")

        for i in range(string_size):
            str_off = struct.unpack("<L", self.dex[str_ids_off+(i*4) : str_ids_off+(i*4)+4])[0]
            str_size = self.dex[str_off]
            self.strings.append((self.dex[str_off+1 : str_off+1+str_size]).decode("utf-8", "ignore"))
            log.debug("type_id : %08x" % (str_ids_off+(i*4)))


        self.string_count = len(self.strings)

    def _parse_type_id(self):
        type_size = self.hdr.get("type_ids_size")
        type_off = self.hdr.get("type_ids_off")

        for i in range(type_size):
            type_idx = struct.unpack("<L", self.dex[type_off+(i*4) : type_off+(i*4)+4])[0]
            self.type_list.append(type_idx)
            log.debug("type_id : %08x" % (type_off+(i*4)))

        self.type_count = len(self.type_list)

    def _parse_proto_id(self):
        proto_size = self.hdr.get('proto_ids_size')
        proto_off = self.hdr.get('proto_ids_off')

        for i in range(proto_size):
            shorty_idx      = struct.unpack("<L", self.dex[proto_off+(i*12) : proto_off+(i*12)+4])[0]
            return_type_idx = struct.unpack("<L", self.dex[proto_off+(i*12)+4 : proto_off+(i*12)+8])[0]
            parameters_off  = struct.unpack("<L", self.dex[proto_off+(i*12)+8 : proto_off+(i*12)+12])[0]

            self.proto_list.append([shorty_idx, return_type_idx, parameters_off])

            log.debug("proto_id : %08x" % (proto_off+(i*12)))

            # string[shorty_idx] - 단축 문자열로 표현된 함수 원형
            # string[type_ids[return_type_idx] - 리턴값 문자열
            # param_num = struct.unpack(params_off:params_off+4)
            # param_off 4 이동
            # param_num 갯수만큼 unpack
            # offset은 2씩

        self.proto_count = len(self.proto_list)

    def _parse_field_id(self):
        field_size = self.hdr.get("field_ids_size")
        field_off = self.hdr.get("field_ids_off")

        for i in range(field_size):
            class_idx   = struct.unpack("<H", self.dex[field_off+(i*8) : field_off+(i*8)+2])[0]
            type_idx    = struct.unpack("<H", self.dex[field_off+(i*8)+2 : field_off+(i*8)+4])[0]
            name_idx    = struct.unpack("<L", self.dex[field_off+(i*8)+4 : field_off+(i*8)+8])[0]

            self.field_list.append([class_idx, type_idx, name_idx])
            log.debug("field list : %08x" % (field_off+(i*8)))

        self.field_count = len(self.field_list)

    def _parse_method_id(self):
        method_size = self.hdr.get("method_ids_size")
        method_off = self.hdr.get("method_ids_off")

        for i in range(method_size):
            class_idx   = struct.unpack("<H", self.dex[method_off+(i*8) : method_off+(i*8)+2])[0]
            proto_idx   = struct.unpack("<H", self.dex[method_off+(i*8)+2 : method_off+(i*8)+4])[0]
            name_idx    = struct.unpack("<L", self.dex[method_off+(i*8)+4 : method_off+(i*8)+8])[0]
            (proto_str, return_str, param_str) = self._parse_parametor(self.proto_list[proto_idx])

            class_str = self.strings[self.type_list[class_idx]]
            name_str = self.strings[name_idx]
            self.method_list.append([class_idx, proto_idx, name_idx])

            log.debug("class_name : %s, offset : %08x " % (class_str, method_off+(i*8)))
            # 메소드 id 파싱할때 methodobject에 정리하는 작업도 같이 진행

        self.method_count = len(self.method_list)

    def _parse_class_def(self):
        class_size = self.hdr.get("class_defs_size")
        class_off = self.hdr.get("class_defs_off")

        for i in range(class_size):
            class_idx           = struct.unpack("<L", self.dex[class_off+(i*0x20) : class_off+(i*0x20)+4])[0]
            access_flags        = struct.unpack("<L", self.dex[class_off+(i*0x20)+4 : class_off+(i*0x20)+8])[0]
            superclass_idx      = struct.unpack("<L", self.dex[class_off+(i*0x20)+8 : class_off+(i*0x20)+12])[0]
            interfaces_off      = struct.unpack("<L", self.dex[class_off+(i*0x20)+12 : class_off+(i*0x20)+16])[0]
            source_file_idx     = struct.unpack("<L", self.dex[class_off+(i*0x20)+16 : class_off+(i*0x20)+20])[0]
            annotations_off     = struct.unpack("<L", self.dex[class_off+(i*0x20)+20 : class_off+(i*0x20)+24])[0]
            class_data_off      = struct.unpack("<L", self.dex[class_off+(i*0x20)+24 : class_off+(i*0x20)+28])[0]
            static_values_off   = struct.unpack("<L", self.dex[class_off+(i*0x20)+28 : class_off+(i*0x20)+32])[0]

            self.class_list.append({"class_idx":class_idx,
                                    "access_flags":access_flags,
                                    "superclass_idx":superclass_idx,
                                    "interfaces_off":interfaces_off,
                                    "source_file_idx":source_file_idx,
                                    "annotations_off":annotations_off,
                                    "class_data_off":class_data_off,
                                    "static_values_off":static_values_off})

        self.class_count = len(self.class_list)

        for i in range(self.class_count):
            class_def = self.class_list[i]
            superclass_str = self.strings[self.type_list[class_def["superclass_idx"]]]
            class_str = self.strings[self.type_list[class_def["class_idx"]]]
            class_off = class_def["class_data_off"]

            log.debug("class_name : %s, offset : %08x " % (class_str, class_off))
            #print("class_name : %s, offset : %x " % (class_str, class_off))
            _sf, _if, _dm, _vm = self.__parse_class_data(class_off)
            self.class_data_list[class_str] = {"static":_sf, "instance":_if, "direct":_dm, "virtual":_vm, }

    def __parse_class_data(self, class_def_off):
        diff = 0

        static_field_list = []
        instance_field_list = []
        direct_method_list = []
        virtual_method_list = []

        if class_def_off == 0:
            return static_field_list, instance_field_list, direct_method_list, virtual_method_list

        static_fields, size = self.uleb128_value(class_def_off)
        class_def_off += size
        instance_fields, size = self.uleb128_value(class_def_off)
        class_def_off += size
        direct_methods, size = self.uleb128_value(class_def_off)
        class_def_off += size
        virtual_methods, size = self.uleb128_value(class_def_off)
        class_def_off += size

        for i in range(static_fields):
            field_idx_diff, access_flags, size = self.encoded_field(class_def_off)
            if i == 0:
                diff = field_idx_diff
            else:
                diff += field_idx_diff
            static_field_list.append([diff, access_flags])
            class_def_off += size

        for i in range(instance_fields):
            field_idx_diff, access_flags, size = self.encoded_field(class_def_off)
            if i == 0:
                diff = field_idx_diff
            else:
                diff += field_idx_diff
            instance_field_list.append([diff, access_flags])
            class_def_off += size

        for i in range(direct_methods):
            method_idx_diff, access_flags, code_off, size = self.encoded_method(class_def_off)
            if i == 0:
                diff = method_idx_diff
            else:
                diff += method_idx_diff
            direct_method_list.append([diff, access_flags, code_off])
            class_def_off += size

        for i in range(virtual_methods):
            method_idx_diff, access_flags, code_off, size = self.encoded_method(class_def_off)
            if i == 0:
                diff = method_idx_diff
            else:
                diff += method_idx_diff
            virtual_method_list.append([diff, access_flags, code_off])
            class_def_off += size

        return static_field_list, instance_field_list, direct_method_list, virtual_method_list

    def _parse_filtered_method_list(self):

        for i in range(len(self.method_list)):
            (class_idx, proto_idx, name_idx) = self.method_list[i]
            class_str = self.strings[self.type_list[class_idx]]
            name_str = self.strings[name_idx]

            skip = False
            for skip_str in self.skip_list:
                if class_str.startswith(skip_str):
                    skip = True

            if skip is False:
                class_method_str = class_str+name_str
                self.filtered_method_list.append(class_method_str)

    def _parse_parametor(self, proto):

        shorty_idx = proto[0]
        proto_str = self.strings[shorty_idx]

        return_idx = proto[1]
        return_str = self.strings[self.type_list[return_idx]]

        param_str = ""
        param_off = proto[2]

        if param_off == 0:
            return proto_str, return_str, param_str

        param_num = struct.unpack("<L", self.dex[param_off:param_off+4])[0]
        param_off += 4
        for i in range(param_num):
            parameter_type = struct.unpack("<H", self.dex[param_off:param_off+2])[0]
            param_str += self.strings[self.type_list[parameter_type]] + " "
            param_off += 2

        return proto_str, return_str, param_str[:-1]

    def _parse_class_bytecode(self):
        log.info("PARSE_CLASS_BYTECODE | class count : %d" % len(self.class_data_list))

        class_count = 0

        for _class in self.class_data_list:
            class_count += 1

            _sf = self.class_data_list[_class].get("static")
            _if = self.class_data_list[_class].get("instance")
            _dm = self.class_data_list[_class].get("direct")
            _vm = self.class_data_list[_class].get("virtual")

            ############START CLASS#############
            if class_count % 100 == 0:
                log.info("(%d/%d) %s : %d, %d, %d, %d" % (class_count, len(self.class_data_list), _class, len(_sf), len(_if), len(_dm), len(_vm)))

            #===========static field============
            sf_ct = 0
            for s in _sf:

                diff, access_flags = s
                field = self.field_list[diff]

                class_idx, type_idx, name_idx = field
                class_str = self.strings[self.type_list[class_idx]]
                type_str = self.strings[self.type_list[type_idx]]
                name_str = self.strings[name_idx]

                log.debug("[%x] %s %s.%s : diff_index : %x" % (sf_ct, type_str, class_str, name_str, diff))

                sf_ct += 1

            #===========instance field============
            if_ct = 0
            for i in _if:
                diff, access_flags = i
                field = self.field_list[diff]

                class_idx, type_idx, name_idx = field
                class_str = self.strings[self.type_list[class_idx]]
                type_str = self.strings[self.type_list[type_idx]]
                name_str = self.strings[name_idx]

                log.debug("[%x] %s %s.%s : diff_index : %x" % (if_ct, type_str, class_str, name_str, diff))

                if_ct += 1

            #===========direct method============
            for d in _dm:
                diff, access_flags, code_off = d
                method = self.method_list[diff]

                class_idx, proto_idx, name_idx = method
                class_str = self.strings[self.type_list[class_idx]]
                name_str = self.strings[name_idx]
                (proto_str, return_str, param_str) = self._parse_parametor(self.proto_list[proto_idx])

                method_key = "%s.%s::%x" % (class_str, name_str, code_off)

                log.debug("%s %s.%s %x, ACCESS_FLAG - %08x" %(return_str, class_str, name_str, code_off, access_flags))
                self._parse_code_item(code_off)

            #===========virtual method============
            for v in _vm:
                diff, access_flags, code_off = v
                method = self.method_list[diff]

                class_idx, proto_idx, name_idx = method
                class_str = self.strings[self.type_list[class_idx]]
                name_str = self.strings[name_idx]
                (proto_str, return_str, param_str) = self._parse_parametor(self.proto_list[proto_idx])

                method_key = "%s.%s::%x" % (class_str, name_str, code_off)

                log.debug("%s %s.%s %x" %(return_str, class_str, name_str, code_off))
                self._parse_code_item(code_off)
            ##############END CLASS###############

    def _parse_code_item(self, off):
        """
        # encoded method에 있는 code_item 파싱
        # registers_size        ushort
        # ins_size              ushort
        # outs_size             ushort
        # treis_size            ushort
        # debug_info_off        uint
        # insns_size            uint
        # insns                 ushort[insns_size]
        # padding               ushort = 0 (optional)
        # tries                 try_item[tries_size] (optional)
        # handlers              encoded_catch_handler_list (optional)

        # insns 계산법
        # ushort[insns_size] == ushort * insns_size == 2 * insns_size
        # ushort 크기는 2임
        """
        if off == 0:
            return -1

        registers_size = struct.unpack("<H", self.dex[off : off+2])[0]
        ins_size = struct.unpack("<H", self.dex[off+2 : off+4])[0]
        outs_size = struct.unpack("<H", self.dex[off+4 : off+6])[0]
        tries_size = struct.unpack("<H", self.dex[off+6 : off+8])[0]
        debug_info_off = struct.unpack("<I", self.dex[off+8 : off+12])[0]
        insns_size = struct.unpack("<I", self.dex[off+12 : off+16])[0]

        tries = []
        ins_off = off+16
        line_ct = 0

        insns = 2 * insns_size
        op_accu_off = 0

        while True:
            op_raw = self.dex[ins_off : ins_off + 1]
            line_ct += 1

            opcode = int(op_raw[0])
            op_data = libs.Dalvik_Bytecode.Opcode.get(opcode)
            op_pointer = op_data.get("size") * 2

            hex_str = self.dex[ins_off : ins_off + op_pointer].hex()
            op_decoded, op_values, op_reference = self._parse_dalvik_instruction(opcode, self.dex[ins_off : ins_off + op_pointer], hex_str)
            ins_off += op_pointer

            op_accu_off += op_pointer

            log.debug("%08x [%d] %s" % (ins_off, line_ct, op_decoded))
            self.last_offset_checker(ins_off)

            if op_accu_off > insns:
                break
            #if op_accu_off > insns+2:
            #    raise CustomExceptions.OpcodeOffsetExceed
        if insns_size % 2 == 1 or tries_size != 0:
            ins_off += 23

        ### Tries Data ###
        for i in range(tries_size):
            _try = struct.unpack(">H", self.dex[ins_off : ins_off+2])[0]
            ins_off += 2
            tries.append(_try)

    def _parse_dalvik_instruction(self, opcode, dalvik_bytes, hex_str):
        # dalvik_bytes는 문자열로 변경되어 들어옴.

        opcode_set = libs.Dalvik_Bytecode.Opcode.get(opcode)
        opcode_name = opcode_set.get("code")
        opcode_format = opcode_set.get("format")
        op_reference = None
        op_ref_data = None
        op_ref_index = -1
        op_values = []
        op_decoded = ""

        if opcode_format == "00x":
            #print("N/A")
            pass

        if opcode_format == "10x":
            op_decoded = ("%s" % opcode_name)
            pass

        if opcode_format == "12x":
            # 2Byte -> dalvik_bytes[0~1]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : High - B, Low - A
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]
            #               0   0  0   0
            #               (OP)   B   A
            # ========================================

            _byte = struct.unpack("B", dalvik_bytes[1:2])[0]
            B, A = self.byte_to_hexdigit(byte=_byte)
            #print("%s v%d, v%d" % (opcode_name, A, B))
            op_decoded = ("%s v%d, v%d" % (opcode_name, A, B))
            op_values = [A, B]

        if opcode_format == "11n":
            # 2Byte -> dalvik_bytes[0~1]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : High - B, Low - A
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]
            #               0   0  0   0
            #               (OP)   B   A
            # ========================================

            _byte = struct.unpack("B", dalvik_bytes[1:2])[0]
            B, A = self.byte_to_hexdigit(byte=_byte)
            #print("%s v%d, #+%04x" % (opcode_name, A, B))
            op_decoded = ("%s v%d, #+%04x" % (opcode_name, A, B))
            op_values = [A]

        if opcode_format == "11x":
            # 2Byte -> dalvik_bytes[0~1]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]
            #               0   0  0   0
            #               (OP)   ( A )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            #print("%s v%d" % (opcode_name, A))
            op_decoded = ("%s v%d" % (opcode_name, A))
            op_values = [A]

        if opcode_format == "10t":
            # 2Byte -> dalvik_bytes[0~1]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]
            #               0   0  0   0
            #               (OP)   ( A )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            #print("%s +%d" % (opcode_name, A))
            op_decoded = ("%s +%d" % (opcode_name, A))

        if opcode_format == "20t":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : 0 (NULL)
            # dalvik_bytes[2~3] : A
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   ( 0 )  (    A     )
            # ========================================
            A = struct.unpack("<H", dalvik_bytes[2:4])[0]
            #print("%s +%04x" % (opcode_name, A))
            op_decoded = ("%s +%04x" % (opcode_name, A))

        if opcode_format == "20bc":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   ( A )  (    B     )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("<H", dalvik_bytes[2:4])[0]
            #print("%s %d, kind@%04x" % (opcode_name, A, B))
            op_decoded = ("%s %d, kind@%04x" % (opcode_name, A, B))
            op_values = [A]

        if opcode_format == "22x":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   ( A )  (    B     )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("<H", dalvik_bytes[2:4])[0]
            #print("%s v%d, v%d" % (opcode_name, A, B))
            op_decoded = ("%s v%d, v%d" % (opcode_name, A, B))
            op_values = [A, B]

        if opcode_format == "21t":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   ( A )  (    B     )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("<H", dalvik_bytes[2:4])[0]
            #print("%s v%d, +%d" % (opcode_name, A, B))
            op_decoded = ("%s v%d, +%d" % (opcode_name, A, B))
            op_values = [A]

        if opcode_format == "21s":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   ( A )  (    B     )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("<H", dalvik_bytes[2:4])[0]
            #print("%s v%d, #+%04x" % (opcode_name, A, B))
            op_decoded = ("%s v%d, #+%04x" % (opcode_name, A, B))
            op_values = [A]

        if opcode_format == "21h":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   ( A )  (    B     )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("<H", dalvik_bytes[2:4])[0]
            #print("%s v%d, #+%04x0000" % (opcode_name, A, B))
            op_decoded = ("%s v%d, #+%04x0000" % (opcode_name, A, B))
            op_values = [A]

        if opcode_format == "21c":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   ( A )  (    B     )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("<H", dalvik_bytes[2:4])[0]

            if opcode == 0x1a:
                op_reference = "string"
                #print("%s v%d, string@%04x" % (opcode_name, A, B))

            if opcode == 0x1c or opcode == 0x1f or opcode == 0x22:
                op_reference = "type"
                #print("%s v%d, type@%04x" % (opcode_name, A, B))

            op_ref_index = B
            op_decoded = ("%s v%d, %s@%04x" % (opcode_name, A, op_reference, B))
            op_values = [A]

        if opcode_format == "23x":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2] : B
            # dalvik_bytes[3] : C
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   ( A )  ( B )  ( C )
            # ========================================
            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("B", dalvik_bytes[2:3])[0]
            C = struct.unpack("B", dalvik_bytes[3:4])[0]

            #print("%s v%d, v%d, v%d" % (opcode_name, A, B, C))
            op_decoded = ("%s v%d, v%d, v%d" % (opcode_name, A, B, C))
            op_values = [A, B, C]

        if opcode_format == "22b":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2] : B
            # dalvik_bytes[3] : C
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   ( A )  ( B )  ( C )
            # ========================================
            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("B", dalvik_bytes[2:3])[0]
            C = struct.unpack("B", dalvik_bytes[3:4])[0]

            #print("%s v%d, v%d, #+%d" % (opcode_name, A, B, C))
            op_decoded = ("%s v%d, v%d, #+%d" % (opcode_name, A, B, C))
            op_values = [A, B]

        if opcode_format == "22t":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : High - B, Low - A
            # dalvik_bytes[2~3] : C
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   B   A  (    C     )
            # ========================================

            _byte = struct.unpack("B", dalvik_bytes[1:2])[0]
            B, A = self.byte_to_hexdigit(byte=_byte)
            C = struct.unpack("<H", dalvik_bytes[2:4])[0]

            #print("%s v%d, v%d, +%d" % (opcode_name, A, B, C))
            op_decoded = ("%s v%d, v%d, +%d" % (opcode_name, A, B, C))
            op_values = [A, B]

        if opcode_format == "22s":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : High - B, Low - A
            # dalvik_bytes[2~3] : C
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   B   A  (    C     )
            # ========================================

            _byte = struct.unpack("B", dalvik_bytes[1:2])[0]
            B, A = self.byte_to_hexdigit(byte=_byte)
            C = struct.unpack("<H", dalvik_bytes[2:4])[0]
            #print("%s v%d, v%d, #+%d" % (opcode_name, A, B, C))
            op_decoded = ("%s v%d, v%d, #+%d" % (opcode_name, A, B, C))
            op_values = [A, B]

        if opcode_format == "22c":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : High - B, Low - A
            # dalvik_bytes[2~3] : C
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   B   A  (    C     )
            # ========================================

            _byte = struct.unpack("B", dalvik_bytes[1:2])[0]
            B, A = self.byte_to_hexdigit(byte=_byte)
            C = struct.unpack("<H", dalvik_bytes[2:4])[0]

            if opcode == 0x20 or opcode == 0x23:
                op_reference = "type"
            else:
                op_reference = "field"
            op_ref_index = C

            #print("%s v%d, v%d, %s@%d" % (opcode_name, A, B, op_reference, C))
            op_decoded = ("%s v%d, v%d, %s@%d" % (opcode_name, A, B, op_reference, C))
            op_values = [A, B]

        if opcode_format == "22cs":
            # 4Byte -> dalvik_bytes[0~3]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : High - B, Low - A
            # dalvik_bytes[2~3] : C
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]
            #               0   0  0   0  0   0  0   0
            #               (OP)   B   A  (    C     )
            # ========================================

            _byte = struct.unpack("B", dalvik_bytes[1:2])[0]
            B, A = self.byte_to_hexdigit(byte=_byte)
            C = struct.unpack("<H", dalvik_bytes[2:4])[0]
            #print("%s v%d, v%d, @%04x" % (opcode_name, A, B, C))
            op_decoded = ("%s v%d, v%d, @%04x" % (opcode_name, A, B, C))
            op_values = [A, B]


        if opcode_format == "30t":
            # 6Byte -> dalvik_bytes[0~5]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : 0
            # dalvik_bytes[2~3] : A_Low
            # dalvik_bytes[4~5] : A_High
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]  [ 4 ]  [ 5 ]
            #               0   0  0   0  0   0  0   0  0   0  0   0
            #               (OP)   ( 0 )  (   A_Low  )  (  A_High  )
            # ========================================

            A_Low = struct.unpack("<H", dalvik_bytes[2:4])[0]
            A_High = struct.unpack("<H", dalvik_bytes[4:6])[0]
            #print("%s +%04x%04x" % (opcode_name, A_High, A_Low))
            op_decoded = ("%s +%04x%04x" % (opcode_name, A_High, A_Low))

        if opcode_format == "32x":
            # 6Byte -> dalvik_bytes[0~5]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : 0
            # dalvik_bytes[2~3] : A
            # dalvik_bytes[4~5] : B
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]  [ 4 ]  [ 5 ]
            #               0   0  0   0  0   0  0   0  0   0  0   0
            #               (OP)   ( 0 )  (    A     )  (    B     )
            # ========================================

            A = struct.unpack("<H", dalvik_bytes[2:4])[0]
            B = struct.unpack("<H", dalvik_bytes[4:6])[0]
            #print("%s v%d, v%d" % (opcode_name, A, B))
            op_decoded = ("%s v%d, v%d" % (opcode_name, A, B))
            op_values = [A, B]

        if opcode_format == "31i":
            # 6Byte -> dalvik_bytes[0~5]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B_Low
            # dalvik_bytes[4~5] : B_High
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]  [ 4 ]  [ 5 ]
            #               0   0  0   0  0   0  0   0  0   0  0   0
            #               (OP)   ( A )  (   B_Low  )  (  B_High  )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B_Low = struct.unpack("<H", dalvik_bytes[2:4])[0]
            B_High = struct.unpack("<H", dalvik_bytes[4:6])[0]
            #print("%s v%d, #+%04x%04x" % (opcode_name, A, B_Low, B_High))
            op_decoded = ("%s v%d, #+%04x%04x" % (opcode_name, A, B_Low, B_High))
            op_values = [A]

        if opcode_format == "31t":
            # 6Byte -> dalvik_bytes[0~5]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B_Low
            # dalvik_bytes[4~5] : B_High
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]  [ 4 ]  [ 5 ]
            #               0   0  0   0  0   0  0   0  0   0  0   0
            #               (OP)   ( A )  (   B_Low  )  (  B_High  )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B_Low = struct.unpack("<H", dalvik_bytes[2:4])[0]
            B_High = struct.unpack("<H", dalvik_bytes[4:6])[0]
            #print("%s v%d, +%04x%04x" % (opcode_name, A, B_Low, B_High))
            op_decoded = ("%s v%d, +%04x%04x" % (opcode_name, A, B_Low, B_High))
            op_values = [A]

        if opcode_format == "31c":
            # 6Byte -> dalvik_bytes[0~5]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B_Low
            # dalvik_bytes[4~5] : B_High
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]  [ 4 ]  [ 5 ]
            #               0   0  0   0  0   0  0   0  0   0  0   0
            #               (OP)   ( A )  (   B_Low  )  (  B_High  )
            # ========================================

            op_reference = "string"

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B_Low = struct.unpack("<H", dalvik_bytes[2:4])[0]
            B_High = struct.unpack("<H", dalvik_bytes[4:6])[0]
            #print("%s v%d, %s@%04x%04x" % (opcode_name, A, op_reference, B_Low, B_High))
            op_decoded = ("%s v%d, %s@%04x%04x" % (opcode_name, A, op_reference, B_Low, B_High))
            op_values = [A]

        if opcode_format == "35c" or opcode_format == "35ms" or opcode_format == "35mi":
            # 6Byte -> dalvik_bytes[0~5]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : High - A, Low - G
            # dalvik_bytes[2~3] : B
            # dalvik_bytes[4] : High - F, Low - E
            # dalvik_bytes[5] : High - D, Low - C
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]  [ 4 ]  [ 5 ]
            #               0   0  0   0  0   0  0   0  0   0  0   0
            #               (OP )  A   G  (    B     )  D   C  F   E
            # ========================================

            _byte = struct.unpack("B", dalvik_bytes[1:2])[0]
            A, G = self.byte_to_hexdigit(byte=_byte)
            B = struct.unpack("<H", dalvik_bytes[2:4])[0]

            _byte = struct.unpack("B", dalvik_bytes[4:5])[0]
            D, C = self.byte_to_hexdigit(byte=_byte)
            _byte = struct.unpack("B", dalvik_bytes[5:6])[0]
            F, E = self.byte_to_hexdigit(byte=_byte)

            # opcode format에 따른 출력값 변화
            # 35c : kind@BBBB
            # 35ms : vtaboff@BBBB
            # 35mi : inline@BBBB

            if opcode == 0x24:
                op_reference = "type"
            if 0x72 >= opcode >= 0x6e:
                op_reference = "method"
            if opcode == 0xfc:
                op_reference = "call_site"

            op_ref_index = B

            if A == 5:
                #print("%s {v%d, v%d, v%d, v%d, v%d}, @%04x" % (opcode_name, C, D, E, F, G, B))
                op_decoded = ("%s {v%d, v%d, v%d, v%d, v%d}, %s@%04x" % (opcode_name, C, D, E, F, G, op_reference, B))
                op_values = [C, D, E, F, G]
            if A == 4:
                #print("%s {v%d, v%d, v%d, v%d}, @%04x" % (opcode_name, C, D, E, F, B))
                op_decoded = ("%s {v%d, v%d, v%d, v%d}, %s@%04x" % (opcode_name, C, D, E, F, op_reference, B))
                op_values = [C, D, E, F]
            if A == 3:
                #print("%s {v%d, v%d, v%d}, @%04x" % (opcode_name, C, D, E, B))
                op_decoded = ("%s {v%d, v%d, v%d}, %s@%04x" % (opcode_name, C, D, E, op_reference, B))
                op_values = [C, D, E]
            if A == 2:
                #print("%s {v%d, v%d}, @%04x" % (opcode_name, C, D, B))
                op_decoded = ("%s {v%d, v%d}, %s@%04x" % (opcode_name, C, D, op_reference, B))
                op_values = [C, D]
            if A == 1:
                #print("%s {v%d}, @%04x" % (opcode_name, C, B))
                op_decoded = ("%s {v%d}, %s@%04x" % (opcode_name, C, op_reference, B))
                op_values = [C]
            if A == 0:
                #print("%s {}, %s@%04x" % (opcode_name, op_reference, B))
                op_decoded = ("%s {}, %s@%04x" % (opcode_name, op_reference, B))

        if opcode_format == "3rc" or opcode_format == "3rms" or  opcode_format == "3rmi":
            # 6Byte -> dalvik_bytes[0~5]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B
            # dalvik_bytes[4~5] : C
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]  [ 4 ]  [ 5 ]
            #               0   0  0   0  0   0  0   0  0   0  0   0
            #               (OP )  ( A )  (    B     )  (    C     )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("<H", dalvik_bytes[2:4])[0]
            C = struct.unpack("<H", dalvik_bytes[4:6])[0]
            N = C + A - 0x1

            if opcode == 0x25:
                op_reference = "type"
            if 0x78 >= opcode >= 0x74:
                op_reference = "method"
            if opcode == 0xfd:
                op_reference = "call_site"
            op_ref_index = B

            # opcode format에 따른 출력값 변화
            # 3rc : type@BBBB
            # 3rms : vtaboff@BBBB
            # 3rmi : inline@BBBB
            #print("%s {v%04x ... v%04x}, @%04x" % (opcode_name, C, N, B))
            op_decoded = ("%s {v%04x ... v%04x}, %s@%04x" % (opcode_name, C, N, op_reference, B))
            for x in range(C, N):
                op_values.append(x)

        if opcode_format == "45cc":
            # 8Byte -> dalvik_bytes[0~7]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : High - A, Low - G
            # dalvik_bytes[2~3] : B
            # dalvik_bytes[4] : High - F, Low - E
            # dalvik_bytes[5] : High - D, Low - C
            # dalvik_bytes[6~7] : H
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]  [ 4 ]  [ 5 ]  [ 6 ]  [ 7 ]
            #               0   0  0   0  0   0  0   0  0   0  0   0  0   0  0   0
            #               (OP )  A   G  (    B     )  D   C  F   E  (    H     )
            # ========================================

            _byte = struct.unpack("B", dalvik_bytes[1:2])[0]
            A, G = self.byte_to_hexdigit(byte=_byte)
            B = struct.unpack("<H", dalvik_bytes[2:4])[0]

            _byte = struct.unpack("B", dalvik_bytes[4:5])[0]
            D, C = self.byte_to_hexdigit(byte=_byte)
            _byte = struct.unpack("B", dalvik_bytes[5:6])[0]
            F, E = self.byte_to_hexdigit(byte=_byte)
            H = struct.unpack("<H", dalvik_bytes[6:8])[0]

            op_reference = "method"
            op_ref_index = B

            if A == 5:
                #print("%s {v%d, v%d, v%d, v%d, v%d}, @%04x, proto@%04x" % (opcode_name, C, D, E, F, G, B, H))
                op_decoded = ("%s {v%d, v%d, v%d, v%d, v%d}, %s@%04x, proto@%04x" % (opcode_name, C, D, E, F, G, op_reference, B, H))
                op_values = [C, D, E, F, G]
            if A == 4:
                #print("%s {v%d, v%d, v%d, v%d}, @%04x, proto@%04x" % (opcode_name, C, D, E, F, B, H))
                op_decoded = ("%s {v%d, v%d, v%d, v%d}, %s@%04x, proto@%04x" % (opcode_name, C, D, E, F, op_reference, B, H))
                op_values = [C, D, E, F]
            if A == 3:
                #print("%s {v%d, v%d, v%d}, @%04x, proto@%04x" % (opcode_name, C, D, E, B, H))
                op_decoded = ("%s {v%d, v%d, v%d}, %s@%04x, proto@%04x" % (opcode_name, C, D, E, op_reference, B, H))
                op_values = [C, D, E]
            if A == 2:
                #print("%s {v%d, v%d}, @%04x, proto@%04x" % (opcode_name, C, D, B, H))
                op_decoded = ("%s {v%d, v%d}, %s@%04x, proto@%04x" % (opcode_name, C, D, op_reference, B, H))
                op_values = [C, D]
            if A == 1:
                #print("%s {v%d}, @%04x, proto@%04x" % (opcode_name, C, B, H))
                op_decoded = ("%s {v%d}, %s@%04x, proto@%04x" % (opcode_name, C, op_reference, B, H))
                op_values = [C]

        if opcode_format == "4rcc":
            # 8Byte -> dalvik_bytes[0~7]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~3] : B
            # dalvik_bytes[4~5] : C
            # dalvik_bytes[6~7] : H
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]  [ 4 ]  [ 5 ]  [ 6 ]  [ 7 ]
            #               0   0  0   0  0   0  0   0  0   0  0   0  0   0  0   0
            #               (OP )  ( A )  (    B     )  (    C     )  (    H     )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("<H", dalvik_bytes[2:4])[0]
            C = struct.unpack("<H", dalvik_bytes[4:6])[0]
            H = struct.unpack("<H", dalvik_bytes[6:8])[0]
            N = C + A - 0x1

            op_reference = "method"
            op_ref_index = B

            #print("%s {v%04x ... v%04x}, meth@%04x, proto@%04x" % (opcode_name, C, N, B, H))
            op_decoded = ("%s {v%04x ... v%04x}, %s@%04x, proto@%04x" % (opcode_name, C, N, op_reference, B, H))
            for x in range(C, N):
                op_values.append(x)

        if opcode_format == "51l":
            # 10yte -> dalvik_bytes[0~9]
            # dalvik_bytes[0] : OPcode
            # dalvik_bytes[1] : A
            # dalvik_bytes[2~9] : B
            # ========================================
            # dalvik_bytes  [ 0 ]  [ 1 ]  [ 2 ]  [ 3 ]  [ 4 ]  [ 5 ]  [ 6 ]  [ 7 ]  [ 8 ]  [ 9 ]
            #               0   0  0   0  0   0  0   0  0   0  0   0  0   0  0   0  0   0  0   0
            #               (OP )  ( A )  (                         B                          )
            # ========================================

            A = struct.unpack("B", dalvik_bytes[1:2])[0]
            B = struct.unpack("<Q", dalvik_bytes[2:10])[0]

            #print("%s v%04x, #+%016x" % (opcode_name, A, B))
            op_decoded = ("%s v%04x, #+%016x" % (opcode_name, A, B))
            op_values = [A]


        # 참조되는 데이터(method, string, type등)의 유효성 검사
        if op_reference is not None:
            index_res = self._index_checker(op_reference=op_reference, op_index=op_ref_index)
            if index_res is True:
                op_ref_data = self._get_reference_data(op_reference, op_ref_index)
            else:
                op_ref_data = "ERROR"

        return op_decoded, op_values, op_ref_data

    def _get_reference_data(self, op_reference, op_index):
        op_original_data = {}
        op_original_data["ref_type"] = op_reference
        if op_reference == "string":
            op_original_data["value"] = self.strings[op_index]

        if op_reference == "field":
            op_original_data["value"] = self.field_list[op_index]

        if op_reference == "method":
            method_dataset = self.method_list[op_index]
            class_idx = method_dataset[0]
            proto_idx = method_dataset[1]
            name_idx = method_dataset[2]

            ## 추출되는 method 데이터리스트
            axr = self.type_list[class_idx]
            _class = self.strings[self.type_list[class_idx]]
            _name = self.strings[name_idx]
            (_proto, _return, _param) = self._parse_parametor(proto=self.proto_list[proto_idx])

            #self._method_scanner(class_str=_class, name_str=_name, param_str=_param)
            #op_original_data = _class + "->" + _name + "(" + _param + ")" + _proto
            op_original_data["value"] = {"axr":axr, "_class":_class, "_name":_name, "_proto":_proto, "_param":_param}

        if op_reference == "type":
            op_original_data["value"] = self.type_list[op_index]

        return op_original_data

    def get_filtered_method_list(self):
        return self.filtered_method_list

    def get_strings(self):
        return self.strings

    def _set_skip_level(self):
        if self.skip_level == "off":
            self.skip_list = []
        elif self.skip_level == "low":
            self.skip_list = self.skip_string_list_small
        elif self.skip_level == "high":
            self.skip_list = self.skip_string_list_full

    def show_header_data(self):
        print("#### HEADER INFO ####")
        for hdr_item in self.hdr:
            print("{0} : {1}".format(hdr_item, self.hdr.get(hdr_item)))

    def show_string_list(self):
        print("#### String List ####")
        for x in range(len(self.strings)):
            print("[%04x] : %s" % (x, self.strings[x]))

    def show_type_list(self):
        print("#### Type List ####")
        for i in range(len(self.type_list)):
            string_idx = self.type_list[i]
            print("[%5d] %s" % (i, self.strings[string_idx]))

    def show_proto_list(self):
        print("#### Prototype List ####")
        for i in range(len(self.proto_list)):
            proto_set = self.proto_list[i]
            idx = proto_set[0]
            print("[%5d] %s" % (i, self.strings[idx]))

    def show_field_list(self):
        print("#### Field List ####")
        for i in range(len(self.field_list)):
            class_str   = self.strings[self.type_list[self.field_list[i][0]]]
            type_str    = self.strings[self.type_list[self.field_list[i][1]]]
            name_str    = self.strings[self.field_list[i][2]]

            msg = "%s %s.%s" % (type_str, class_str, name_str)
            print("[%5d] %s" % (i, msg))

    def show_method_list(self):
        print("#### Method List ####")
        for i in range(len(self.method_list)):
            (class_idx, proto_idx, name_idx) = self.method_list[i]
            class_str = self.strings[self.type_list[class_idx]]
            name_str = self.strings[name_idx]

            print("[%04x] METHOD:%s.%s()" % (i, class_str, name_str))

    def show_class_def_list(self):
        print("#### Class Def List ####")
        for cls in self.class_list:
            class_str = self.strings[self.type_list[cls[0]]]
            print("%s: %06x" % (class_str, cls[6]))

    def show_filtered_method_list(self):
        for i in range(len(self.filtered_method_list)):
            print("[%5d] %s()" % (i, self.filtered_method_list[i]))

    def show_target_method(self, t_method):
        for class_method in self.filtered_method_list:
            pe = class_method.split(";")
            #print(class_method)

            try:
                me = pe[1]
            except:
                continue

            if me.find(t_method.lower()) != -1 or me.find(t_method.upper()) != -1:
                print("FOUND : %s" % class_method)

    def _isDexNull(self):
        if self.dex == None:
            return True
        else:
            return False

    def _isValidDex(self):
        if self.dex[0:3] == b'dex' and len(self.dex) > 0x70:
            return True
        else:
            return False

    def _isValidSkipLevel(self):
        if self.skip_level == 'high' or self.skip_level == 'low' or self.skip_level == "off":
            return True
        else:
            return False

    def encoded_field(self, off):
        off1 = off
        field_idx_diff, size = self.uleb128_value(off1)
        off1 += size
        access_flags, size = self.uleb128_value(off1)
        off1 += size
        size = off1 - off

        return field_idx_diff, access_flags, size

    def encoded_method(self, off):
        off1 = off
        method_idx_diff, size = self.uleb128_value(off1)
        off1 += size
        access_flags, size = self.uleb128_value(off1)
        off1 += size
        code_off, size = self.uleb128_value(off1)
        off1 += size

        size = off1 - off
        return method_idx_diff, access_flags, code_off, size

    def uleb128_value(self, off):
        size = 1
        result = ord(chr(self.dex[off+0]))

        if result > 0x7f:
            cur = ord(chr(self.dex[off+1]))
            result = (result & 0x7f) | ((cur & 0x7f) << 7)
            size += 1

            if cur > 0x7f:
                cur = ord(chr(self.dex[off+2]))
                result |= ((cur & 0x7f) << 14)
                size += 1
                if cur > 0x7f:
                    cur = ord(chr(self.dex[off+3]))
                    result |= ((cur & 0x7f) << 21)
                    size += 1
                    if cur > 0x7f:
                        cur = ord(chr(self.dex[off+4]))
                        result |= (cur << 28)
                        size += 1
        return result, size

    def _index_checker(self, op_reference, op_index):
        if op_reference == "string":
            if self.string_count > op_index >= 0:
                return True
            else:
                return False

        if op_reference == "field":
            if self.field_count > op_index >= 0:
                return True
            else:
                return False

        if op_reference == "method":
            if self.method_count > op_index >= 0:
                return True
            else:
                return False

        if op_reference == "type":
            if self.type_count > op_index >= 0:
                return True
            else:
                return False

    def byte_to_hexdigit(self, byte):
        high_digit = int(byte / 16)
        low_digit = byte % 16
        return (high_digit, low_digit)

    def _str_to_hex_byte(self, hex_string):
        bytes = b""
        for c in hex_string:
            byte = self._char_to_byte(c)
            bytes += byte
        return bytes

    def _char_to_byte(self, char):
        if char == "0":     return struct.pack("B", 0x0)
        if char == "1":     return struct.pack("B", 0x1)
        if char == "2":     return struct.pack("B", 0x2)
        if char == "3":     return struct.pack("B", 0x3)
        if char == "4":     return struct.pack("B", 0x4)
        if char == "5":     return struct.pack("B", 0x5)
        if char == "6":     return struct.pack("B", 0x6)
        if char == "7":     return struct.pack("B", 0x7)
        if char == "8":     return struct.pack("B", 0x8)
        if char == "9":     return struct.pack("B", 0x9)
        if char == "a":     return struct.pack("B", 0xa)
        if char == "b":     return struct.pack("B", 0xb)
        if char == "c":     return struct.pack("B", 0xc)
        if char == "d":     return struct.pack("B", 0xd)
        if char == "e":     return struct.pack("B", 0xe)
        if char == "f":     return struct.pack("B", 0xf)

    def last_offset_checker(self, offset):
        if self.last_offset < offset:
            self.last_offset = offset


def main():

    st = time.time()
    log.info("MAIN START")
    test1 = DexAnalyzer("off")

    test1.setDex_Apk(sys.argv[1])
    test1.analyze()

    et = time.time()
    total_running_time = et - st
    log.info("MAIN END. Running t"
             "ime:%.4f" % total_running_time)


if __name__ == "__main__":
    main()
