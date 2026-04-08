#include <windows.h>
#include <print>
#include <TlHelp32.h>
#include <winnt.h>
#pragma comment(lib, "ntdll.lib")

#define STATUS_SUCCESS 0x00000000L

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING ObjectName;
    ULONG Attributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
    );

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtClose(
    _In_ _Post_ptr_invalid_ HANDLE Handle
);
EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);


typedef _Function_class_(USER_THREAD_START_ROUTINE)
NTSTATUS NTAPI USER_THREAD_START_ROUTINE(
    _In_ PVOID ThreadParameter
);
typedef USER_THREAD_START_ROUTINE* PUSER_THREAD_START_ROUTINE;

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
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

_Struct_size_bytes_(TotalLength)
typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
);

class Injector {
    public:
    Injector(std::string name) : process_name(name) {}
    ~Injector() {
        if (process_handle) {
            NtClose(process_handle);
        }

    }

    void inject(std::string module_path) {
        set_pid();
        std::println("{} PID: {}", process_name, process_id);
        if (!process_id) {
            std::println("Process not found!");
            return;
        }
        if (module_path.empty()) {
            std::println("Module path is empty!");
            return;
        }
        //process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
        CLIENT_ID id{};
        id.UniqueProcess = reinterpret_cast<HANDLE>(process_id);
        OBJECT_ATTRIBUTES obj_attr{};
        obj_attr.Length = sizeof(OBJECT_ATTRIBUTES);
        long error = NtOpenProcess(&process_handle, PROCESS_ALL_ACCESS, &obj_attr, &id);
        std::println("{}", error);
        LPVOID path_ptr = VirtualAllocEx(process_handle, 0, module_path.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        long status = NtAllocateVirtualMemory(process_handle, 0, 0, 0, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (status != STATUS_SUCCESS) {
            std::println("Failed to allocate memory in target process!\n Error: {}", status);
        }
        NtWriteVirtualMemory(process_handle, path_ptr, module_path.data(), module_path.size(), 0);

        // HANDLE thread = CreateRemoteThreadEx(process_handle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, path_ptr, 0, 0, 0);

        OBJECT_ATTRIBUTES thread_obj_attr{};
        thread_obj_attr.Length = sizeof(OBJECT_ATTRIBUTES);
        HANDLE thread{};
        status = NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, &thread_obj_attr, process_handle, (PUSER_THREAD_START_ROUTINE)LoadLibraryA, path_ptr, 0, 0, 0, 0, 0);
        if (status != STATUS_SUCCESS) {
            std::println("Failed to create remote thread!\n Error: {}", status);
        }

        if (thread) {
            NtWaitForSingleObject(thread, 0, PLARGE_INTEGER(MAXLONG));
            NtFreeVirtualMemory(process_handle, &path_ptr, 0, MEM_RELEASE);
            NtClose(thread);
        }
    }

    private:
    void set_pid() {
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe{};
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hsnap, &pe)) {
            do {
                if (process_name.compare(pe.szExeFile) == 0) {
                    process_id = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hsnap, &pe));
        }
    }
    std::string process_name{};
    DWORD process_id{};
    HANDLE process_handle{};
};

auto main() -> int {
    Injector injector("Zed.exe");
    injector.inject("C:\\Users\\0\\Downloads\\msg.dll");

    return 0;
}
