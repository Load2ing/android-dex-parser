class ManifestGetDataError(Exception):
    def __str__(self):
        return "[ERR/axmlParser] FAILED TO GET PACKAGE NAME"

class DexHeaderError(Exception):
    def __str__(self):
        return "[ERR/DexAnalyzer] DEX HEADER ERROR"

class DexSizeMismatch(Exception):
    def __str__(self):
        return "[ERR/DexAnalyzer] DEX SIZE MISMATCH."

class DexIsEmpty(Exception):
    def __str__(self):
        return "[ERR/DexAnalyzer] DEX IS NULL"

class SkipLevelError(Exception):
    def __str__(self):
        return "[ERR/DexAnalyzer] INPUT SKIP LEVEL ERROR"

class OpcodeOffsetExceed(Exception):
    def __str__(self):
        return "[ERR/DexAnalyzer] 오프셋이 현재 OPCODE의 범위를 초과함"
