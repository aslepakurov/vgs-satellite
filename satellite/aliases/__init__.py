from enum import Enum, unique


class RedactFailed(BaseException):
    pass


class RevealFailed(BaseException):
    pass


@unique
class AliasGeneratorType(Enum):
    FPE_SIX_T_FOUR = 'FPE_SIX_T_FOUR'
    FPE_T_FOUR = 'FPE_T_FOUR'
    NON_LUHN_FPE_ALPHANUMERIC = 'NON_LUHN_FPE_ALPHANUMERIC'
    PFPT = 'PFPT'
    RAW_UUID = 'RAW_UUID'
    UUID = 'UUID'


@unique
class AliasStoreType(Enum):
    PERSISTENT = 'PERSISTENT'
    VOLATILE = 'VOLATILE'
