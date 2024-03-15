#include <Windows.h>
#include <iostream>

#define CALLING_CONVERTION					FALSE
#define OB_OPEN_OIBJECT_BY_POINTER_TEST		FALSE
#define NT_OPENPROCESS_TEST					FALSE
#define MAIN								TRUE

#if OB_OPEN_OBJECT_BY_POINTER
#include <ntifs.h>

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE {
	KernelMode,
	UserMode,
	MaximumMode
} MODE;

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
	_In_ PVOID Object,
	_In_ ULONG HandleAttributes,
	_In_opt_ PACCESS_STATE PassedAccessState,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_Out_ PHANDLE Handle
);

#endif

#if CALLING_CONVERTION
void Function(int rcx, int rdx, int r8, int r9, int stack1, int stack2, int stack3) {
	printf_s("rcx: %d, rdx: %d, r8: %d, r9: %d, stack1: %d, stack2: %d, stack3: %d", rcx, rdx, r8, r9, stack1, stack2, stack3);
	printf("Calling\n");
};

int main() {
	const static int rcx = 1, rdx = 2, r8 = 3, r9 = 4, stack1 = 5, stack2 = 6, stack3 = 7;
	Function(rcx, rdx, r8, r9, stack1, stack2, stack3);
	return 0;
};
#endif

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
BOOL CallNtCreateThreadEx(HANDLE processHandle, LPTHREAD_START_ROUTINE remoteThreadFunc, LPVOID remoteBuf);

/*
NTSTATUS
NTAPI
NtCreateThreadEx(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PUSER_THREAD_START_ROUTINE StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	_In_ SIZE_T ZeroBits,
	_In_ SIZE_T StackSize,
	_In_ SIZE_T MaximumStackSize,
	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);
*/

//전역 함수 포인터 선언
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;

} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
	_In_ PVOID ThreadParameter
	);

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


typedef NTSTATUS  (*pNtCreateThreadEx)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ LPTHREAD_START_ROUTINE StartRoutine,
	_In_opt_ LPVOID Argument,
	_In_ BOOL CreateFlags, // THREAD_CREATE_FLAGS_*
	_In_ SIZE_T ZeroBits,
	_In_ SIZE_T StackSize,
	_In_ SIZE_T MaximumStackSize,
	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
	);


int main() {
	DWORD pid = 0;
	wchar_t dllPath[MAX_PATH] = { 0, };

	auto result = SetForcePrivilege();
	if (!result) exit(1);

	std::cout << "PID : "; std::cin >> pid;
	
	while (getchar() != '\n');
	std::cout << "DLL Path : ";
	_getws_s(dllPath);

	Injection(pid,dllPath);

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

	auto result = CallNtCreateThreadEx(procHandle, (LPTHREAD_START_ROUTINE)procAddr, injectionDLLPathAddr);
	if (!result) {
		cerr << "CallNtCreateThreadEx" << endl;
		return FALSE;
	};

	WaitForSingleObject(remoteThreadHandle, INFINITY);

	CloseHandle(procHandle);

	return TRUE;
};

BOOL CallNtCreateThreadEx(HANDLE processHandle, LPTHREAD_START_ROUTINE remoteThreadFunc, LPVOID remoteBuf) {
	HMODULE ntdll = NULL;
	HANDLE threadHandle = NULL;
	void* originFuncAddr = NULL;

	ntdll = GetModuleHandle(L"ntdll.dll");
	if (ntdll == NULL) {
		cerr << "ntdll" << endl;
		return FALSE;
	};

	originFuncAddr = GetProcAddress(ntdll, "NtCreateThreadEx");
	if (originFuncAddr == NULL) {
		cerr << "originFuncAddr" << endl;
		return FALSE;
	};

	auto result = ((pNtCreateThreadEx)originFuncAddr)(&threadHandle, 0x1FFFFF, NULL, processHandle, remoteThreadFunc, remoteBuf, NULL, NULL, NULL, NULL, NULL);
	if (result != 0) {
		cerr << "NtCreateThrreadEx" << endl;
		return FALSE;
	};

	return TRUE;
};
#endif