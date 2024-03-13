#include <Windows.h>
#include <iostream>

#define OB_OPEN_OIBJECT_BY_POINTER_TEST TRUE
#define NT_OPENPROCESS_TEST		FALSE
#define MAIN					FALSE

#if OB_OPEN_OIBJECT_BY_POINTER_TEST

typedef struct _SECURITY_SUBJECT_CONTEXT {
	PACCESS_TOKEN                ClientToken;
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
	PACCESS_TOKEN                PrimaryToken;
	PVOID                        ProcessAuditId;

} SECURITY_SUBJECT_CONTEXT, * PSECURITY_SUBJECT_CONTEXT;

typedef struct _INITIAL_PRIVILEGE_SET
{
	ULONG PrivilegeCount;
	ULONG Control;
	LUID_AND_ATTRIBUTES Privilege[3];
} INITIAL_PRIVILEGE_SET, * PINITIAL_PRIVILEGE_SET;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _ACCESS_STATE {
	LUID                     OperationID;
	BOOLEAN                  SecurityEvaluated;
	BOOLEAN                  GenerateAudit;
	BOOLEAN                  GenerateOnClose;
	BOOLEAN                  PrivilegesAllocated;
	ULONG                    Flags;
	ACCESS_MASK              RemainingDesiredAccess;
	ACCESS_MASK              PreviouslyGrantedAccess;
	ACCESS_MASK              OriginalDesiredAccess;
	SECURITY_SUBJECT_CONTEXT SubjectSecurityContext;
	PSECURITY_DESCRIPTOR     SecurityDescriptor;
	PVOID                    AuxData;
	union {
		INITIAL_PRIVILEGE_SET InitialPrivilegeSet;
		PRIVILEGE_SET         PrivilegeSet;
	} Privileges;
	BOOLEAN                  AuditPrivileges;
	UNICODE_STRING           ObjectName;
	UNICODE_STRING           ObjectTypeName;
} ACCESS_STATE, * PACCESS_STATE;

const BYTE systemACcessStateData[] = { 0x00,0x8b,0x39,0x58,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x1f,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x1f,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5f,0xb0,0xb3,0x60,0xff,0xff,0xe3,0x0a,0x00,0x00,0x20,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x13,0x63,0x68,0xe0,0xff,0xff,0x9a,0x8a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

int main() {
	//std::cout << "ACCESS_STATE size : " << sizeof(ACCESS_STATE) << std::endl;
	ACCESS_STATE ac = { 0, };
	memcpy(&ac, systemACcessStateData, sizeof(systemACcessStateData));

	return 0;
};
#endif

#if NT_OPENPROCESS_TEST

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

typedef struct _OBJECT_ATTRIBUTES64 {
	ULONG Length;
	ULONG64 RootDirectory;
	ULONG64 ObjectName;
	ULONG Attributes;
	ULONG64 SecurityDescriptor;
	ULONG64 SecurityQualityOfService;
} OBJECT_ATTRIBUTES64;
typedef OBJECT_ATTRIBUTES64* POBJECT_ATTRIBUTES64;
typedef CONST OBJECT_ATTRIBUTES64* PCOBJECT_ATTRIBUTES64;

int main() {
	int size = sizeof(OBJECT_ATTRIBUTES64::Attributes);
	printf("size[1] : %d \n", size);

	size = sizeof(OBJECT_ATTRIBUTES64::Length);
	printf("size[2] : %d \n", size);

	size = sizeof(OBJECT_ATTRIBUTES64::ObjectName);
	printf("size[3] : %d \n", size);
	return 0;
};

#endif

#if MAIN
using namespace std;

BOOL SetForcePrivilege();
BOOL Injection(const DWORD pid, const wchar_t* dllPath);

int main() {
	DWORD pid = 0;

	auto result = SetForcePrivilege();
	if (!result) exit(1);

	std::cout << "PID : "; std::cin >> pid;
	Injection(pid, L"D:\\Source\\KernelDLLInjection\\test.dll");

	return 0;
};

BOOL SetForcePrivilege() {
	HANDLE token = NULL;
	LUID luid = { 0, };
	TOKEN_PRIVILEGES tp = { 0, };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token)) {
		cerr << "token" << endl;
		return FALSE;
	};

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		cerr << "luid" << endl;
		return FALSE;
	};

	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		cerr << "tp" << endl;
		return FALSE;
	};

	return TRUE;
};

BOOL Injection(const DWORD pid, const wchar_t* dllPath) {
	HANDLE procHandle = NULL, remoteThreadHandle = NULL;
	HMODULE dll = NULL;
	void* procAddr = NULL, * injectionDLLPathAddr = NULL;

	procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (procHandle == NULL) {
		cerr << "procHandle" << endl;
		return FALSE;
	};

	injectionDLLPathAddr = VirtualAllocEx(procHandle, NULL, MAX_PATH, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (injectionDLLPathAddr == NULL) {
		cerr << "injectionDLLPathAddr" << endl;
		return FALSE;
	}

	SIZE_T written = 0;

	if (!WriteProcessMemory(procHandle, injectionDLLPathAddr, dllPath, MAX_PATH, &written)) {
		cerr << "WriteProcessMemory" << endl;
		return FALSE;
	};

	dll = GetModuleHandle(L"kernel32.dll");
	if (dll == NULL) {
		cerr << "dll" << endl;
		return FALSE;
	};

	procAddr = GetProcAddress(dll, "LoadLibraryW");
	if (procAddr == NULL) {
		cerr << "procAddr" << endl;
		return FALSE;
	};

	remoteThreadHandle = CreateRemoteThread(procHandle, NULL, 0, (LPTHREAD_START_ROUTINE)procAddr, injectionDLLPathAddr, NULL, NULL);
	if (remoteThreadHandle == NULL) {
		cerr << "remoteThreadHandle" << endl;
		return FALSE;
	};

	WaitForSingleObject(remoteThreadHandle, INFINITY);

	CloseHandle(procHandle);

	return TRUE;
};
#endif