from struct import Struct

HEADER_STRUCT = Struct('>HII')

# Trusted Platform Module Library Part 2: Structures
# Family "2.0"
# Level 00 Revision 01.59
# https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf

TPM_ST = {
    0x00C4: "RSP_COMMAND",
    0x8000: "NULL",
    0x8001: "NO_SESSIONS",
    0x8002: "SESSIONS",
    0x8003: "reserved",
    0x8004: "reserved",
    0x8014: "ATTEST_NV",
    0x8015: "ATTEST_COMMAND_AUDIT",
    0x8016: "ATTEST_SESSION_AUDIT",
    0x8017: "ATTEST_CERTIFY",
    0x8018: "ATTEST_QUOTE",
    0x8019: "ATTEST_TIME",
    0x801A: "ATTEST_CREATION",
    0x801B: "reserved",
    0x801C: "ATTEST_NV_DIGEST",
    0x8021: "CREATION",
    0x8022: "VERIFIED",
    0x8023: "AUTH_SECRET",
    0x8024: "HASHCHECK",
    0x8025: "AUTH_SIGNED",
    0x8029: "FU_MANIFEST",
}

TPM_CC = {
    0x0000011F: "NV_UndefineSpaceSpecial",
    0x00000120: "EvictControl",
    0x00000121: "HierarchyControl",
    0x00000122: "NV_UndefineSpace",
    0x00000124: "ChangeEPS",
    0x00000125: "ChangePPS",
    0x00000126: "Clear",
    0x00000127: "ClearControl",
    0x00000128: "ClockSet",
    0x00000129: "HierarchyChangeAuth",
    0x0000012A: "NV_DefineSpace",
    0x0000012B: "PCR_Allocate",
    0x0000012C: "PCR_SetAuthPolicy",
    0x0000012D: "PP_Commands",
    0x0000012E: "SetPrimaryPolicy",
    0x0000012F: "FieldUpgradeStart",
    0x00000130: "ClockRateAdjust",
    0x00000131: "CreatePrimary",
    0x00000132: "NV_GlobalWriteLock",
    0x00000133: "GetCommandAuditDigest",
    0x00000134: "NV_Increment",
    0x00000135: "NV_SetBits",
    0x00000136: "NV_Extend",
    0x00000137: "NV_Write",
    0x00000138: "NV_WriteLock",
    0x00000139: "DictionaryAttackLockReset",
    0x0000013A: "DictionaryAttackParameters",
    0x0000013B: "NV_ChangeAuth",
    0x0000013C: "PCR_Event",
    0x0000013D: "PCR_Reset",
    0x0000013E: "SequenceComplete",
    0x0000013F: "SetAlgorithmSet",
    0x00000140: "SetCommandCodeAuditStatus",
    0x00000141: "FieldUpgradeData",
    0x00000142: "IncrementalSelfTest",
    0x00000143: "SelfTest",
    0x00000144: "Startup",
    0x00000145: "Shutdown",
    0x00000146: "StirRandom",
    0x00000147: "ActivateCredential",
    0x00000148: "Certify",
    0x00000149: "PolicyNV",
    0x0000014A: "CertifyCreation",
    0x0000014B: "Duplicate",
    0x0000014C: "GetTime",
    0x0000014D: "GetSessionAuditDigest",
    0x0000014E: "NV_Read",
    0x0000014F: "NV_ReadLock",
    0x00000150: "ObjectChangeAuth",
    0x00000151: "PolicySecret",
    0x00000152: "Rewrap",
    0x00000153: "Create",
    0x00000154: "ECDH_ZGen",
    0x00000155: "HMAC",
    0x00000155: "MAC",
    0x00000156: "Import",
    0x00000157: "Load",
    0x00000158: "Quote",
    0x00000159: "RSA_Decrypt",
    0x0000015B: "HMAC_Start",
    0x0000015B: "MAC_Start",
    0x0000015C: "SequenceUpdate",
    0x0000015D: "Sign",
    0x0000015E: "Unseal",
    0x00000160: "PolicySigned",
    0x00000161: "ContextLoad",
    0x00000162: "ContextSave",
    0x00000163: "ECDH_KeyGen",
    0x00000164: "EncryptDecrypt",
    0x00000165: "FlushContext",
    0x00000167: "LoadExternal",
    0x00000168: "MakeCredential",
    0x00000169: "NV_ReadPublic",
    0x0000016A: "PolicyAuthorize",
    0x0000016B: "PolicyAuthValue",
    0x0000016C: "PolicyCommandCode",
    0x0000016D: "PolicyCounterTimer",
    0x0000016E: "PolicyCpHash",
    0x0000016F: "PolicyLocality",
    0x00000170: "PolicyNameHash",
    0x00000171: "PolicyOR",
    0x00000172: "PolicyTicket",
    0x00000173: "ReadPublic",
    0x00000174: "RSA_Encrypt",
    0x00000176: "StartAuthSession",
    0x00000177: "VerifySignature",
    0x00000178: "ECC_Parameters",
    0x00000179: "FirmwareRead",
    0x0000017A: "GetCapability",
    0x0000017B: "GetRandom",
    0x0000017C: "GetTestResult",
    0x0000017D: "Hash",
    0x0000017E: "PCR_Read",
    0x0000017F: "PolicyPCR",
    0x00000180: "PolicyRestart",
    0x00000181: "ReadClock",
    0x00000182: "PCR_Extend",
    0x00000183: "PCR_SetAuthValue",
    0x00000184: "NV_Certify",
    0x00000185: "EventSequenceComplete",
    0x00000186: "HashSequenceStart",
    0x00000187: "PolicyPhysicalPresence",
    0x00000188: "PolicyDuplicationSelect",
    0x00000189: "PolicyGetDigest",
    0x0000018A: "TestParms",
    0x0000018B: "Commit",
    0x0000018C: "PolicyPassword",
    0x0000018D: "ZGen_2Phase",
    0x0000018E: "EC_Ephemeral",
    0x0000018F: "PolicyNvWritten",
    0x00000190: "PolicyTemplate",
    0x00000191: "CreateLoaded",
    0x00000192: "PolicyAuthorizeNV",
    0x00000193: "EncryptDecrypt2",
    0x00000194: "AC_GetCapability",
    0x00000195: "AC_Send",
    0x00000196: "Policy_AC_SendSelect",
    0x00000197: "CertifyX509",
    0x00000198: "ACT_SetTimeout",
    0x20000000: "Vendor_TCG_Test",
}

TPM_RC = {
    0x000:          "SUCCESS",
    0x01E:          "BAD_TAG",
    0x100 + 0x000:  "INITIALIZE",
    0x100 + 0x001:  "FAILURE",
    0x100 + 0x003:  "SEQUENCE",
    0x100 + 0x00B:  "PRIVATE",
    0x100 + 0x019:  "HMAC",
    0x100 + 0x020:  "DISABLED",
    0x100 + 0x021:  "EXCLUSIVE",
    0x100 + 0x024:  "AUTH_TYPE",
    0x100 + 0x025:  "AUTH_MISSING",
    0x100 + 0x026:  "POLICY",
    0x100 + 0x027:  "PCR",
    0x100 + 0x028:  "PCR_CHANGED",
    0x100 + 0x02D:  "UPGRADE",
    0x100 + 0x02E:  "TOO_MANY_CONTEXTS",
    0x100 + 0x02F:  "AUTH_UNAVAILABLE",
    0x100 + 0x030:  "REBOOT",
    0x100 + 0x031:  "UNBALANCED",
    0x100 + 0x042:  "COMMAND_SIZE",
    0x100 + 0x043:  "COMMAND_CODE",
    0x100 + 0x044:  "AUTHSIZE",
    0x100 + 0x045:  "AUTH_CONTEXT",
    0x100 + 0x046:  "NV_RANGE",
    0x100 + 0x047:  "NV_SIZE",
    0x100 + 0x048:  "NV_LOCKED",
    0x100 + 0x049:  "NV_AUTHORIZATION",
    0x100 + 0x04A:  "NV_UNINITIALIZED",
    0x100 + 0x04B:  "NV_SPACE",
    0x100 + 0x04C:  "NV_DEFINED",
    0x100 + 0x050:  "BAD_CONTEXT",
    0x100 + 0x051:  "CPHASH",
    0x100 + 0x052:  "PARENT",
    0x100 + 0x053:  "NEEDS_TEST",
    0x100 + 0x054:  "NO_RESULT",
    0x100 + 0x055:  "SENSITIVE",
    0x080 + 0x001:  "ASYMMETRIC",
    0x080 + 0x002:  "ATTRIBUTES",
    0x080 + 0x003:  "HASH",
    0x080 + 0x004:  "VALUE",
    0x080 + 0x005:  "HIERARCHY",
    0x080 + 0x007:  "KEY_SIZE",
    0x080 + 0x008:  "MGF",
    0x080 + 0x009:  "MODE",
    0x080 + 0x00A:  "TYPE",
    0x080 + 0x00B:  "HANDLE",
    0x080 + 0x00C:  "KDF",
    0x080 + 0x00D:  "RANGE",
    0x080 + 0x00E:  "AUTH_FAIL",
    0x080 + 0x00F:  "NONCE",
    0x080 + 0x010:  "PP",
    0x080 + 0x012:  "SCHEME",
    0x080 + 0x015:  "SIZE",
    0x080 + 0x016:  "SYMMETRIC",
    0x080 + 0x017:  "TAG",
    0x080 + 0x018:  "SELECTOR",
    0x080 + 0x01A:  "INSUFFICIENT",
    0x080 + 0x01B:  "SIGNATURE",
    0x080 + 0x01C:  "KEY",
    0x080 + 0x01D:  "POLICY_FAIL",
    0x080 + 0x01F:  "INTEGRITY",
    0x080 + 0x020:  "TICKET",
    0x080 + 0x021:  "RESERVED_BITS",
    0x080 + 0x022:  "BAD_AUTH",
    0x080 + 0x023:  "EXPIRED",
    0x080 + 0x024:  "POLICY_CC",
    0x080 + 0x025:  "BINDING",
    0x080 + 0x026:  "CURVE",
    0x080 + 0x027:  "ECC_POINT",
    0x900 + 0x001:  "CONTEXT_GAP",
    0x900 + 0x002:  "OBJECT_MEMORY",
    0x900 + 0x003:  "SESSION_MEMORY",
    0x900 + 0x004:  "MEMORY",
    0x900 + 0x005:  "SESSION_HANDLES",
    0x900 + 0x006:  "OBJECT_HANDLES",
    0x900 + 0x007:  "LOCALITY",
    0x900 + 0x008:  "YIELDED",
    0x900 + 0x009:  "CANCELED",
    0x900 + 0x00A:  "TESTING",
    0x900 + 0x010:  "REFERENCE_H0",
    0x900 + 0x011:  "REFERENCE_H1",
    0x900 + 0x012:  "REFERENCE_H2",
    0x900 + 0x013:  "REFERENCE_H3",
    0x900 + 0x014:  "REFERENCE_H4",
    0x900 + 0x015:  "REFERENCE_H5",
    0x900 + 0x016:  "REFERENCE_H6",
    0x900 + 0x018:  "REFERENCE_S0",
    0x900 + 0x019:  "REFERENCE_S1",
    0x900 + 0x01A:  "REFERENCE_S2",
    0x900 + 0x01B:  "REFERENCE_S3",
    0x900 + 0x01C:  "REFERENCE_S4",
    0x900 + 0x01D:  "REFERENCE_S5",
    0x900 + 0x01E:  "REFERENCE_S6",
    0x900 + 0x020:  "NV_RATE",
    0x900 + 0x021:  "LOCKOUT",
    0x900 + 0x022:  "RETRY",
    0x900 + 0x023:  "NV_UNAVAILABLE",
    0x900 + 0x7F:   "NOT_USED",
}

class PacketParser:
    data: bytearray()
    hdr_tag: int
    hdr_size: int
    hdr_code: int
    is_valid: bool

    def __init__(self, data, is_response):
        self.data = data
        self.is_response = is_response
        self.hdr_tag = None
        self.hdr_size = None
        self.hdr_code = None
        self.is_valid = False

        self._parse_header()

    def get_header(self):
        return self.data[:HEADER_STRUCT.size]

    def get_body(self):
        return self.data[HEADER_STRUCT.size:]

    def get_tag_name(self):
        if self.hdr_tag is None:
            return 'None'
        elif self.hdr_tag not in TPM_ST:
            return f'Unknown (0x{self.hdr_tag:04x})'
        return TPM_ST[self.hdr_tag]

    def get_command_code_name(self):
        if self.is_response:
            raise ValueError('Not a command')
        elif self.hdr_code is None:
            return 'None'
        elif self.hdr_code not in TPM_CC:
            return f'Unknown (0x{self.hdr_code:04x})'
        return TPM_CC[self.hdr_code]

    def get_response_code_name(self):
        if not self.is_response:
            raise ValueError('Not a response')
        elif self.hdr_code is None:
            return 'None'
        elif self.hdr_code not in TPM_RC:
            return f'Unknown (0x{self.hdr_code:04x})'
        return TPM_RC[self.hdr_code]

    def get_code_name(self):
        if self.is_response:
            return self.get_response_code_name()
        else:
            return self.get_command_code_name()

    def _parse_header(self):
        if len(self.data) < HEADER_STRUCT.size:
            return
        self.hdr_tag, self.hdr_size, self.hdr_code = HEADER_STRUCT.unpack(self.get_header())

        if self.hdr_tag not in TPM_ST:
            return
        elif TPM_ST[self.hdr_tag] not in ("NO_SESSIONS", "SESSIONS"):
            return
        elif self.hdr_size != len(self.data):
            return
        elif self.is_response and self.hdr_code not in TPM_RC:
            return
        elif not self.is_response and self.hdr_code not in TPM_CC:
            return

        self.is_valid = True
