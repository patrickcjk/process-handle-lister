#include "main.h"

EXTERN_C NTSTATUS NtDuplicateObject(
    IN  HANDLE SourceProcessHandle,
    IN  HANDLE SourceHandle,
    IN  HANDLE TargetProcessHandle OPTIONAL,
    OUT PHANDLE TargetHandle OPTIONAL,
    IN  ACCESS_MASK DesiredAccess,
    IN  ULONG HandleAttributes,
    IN  ULONG Options
);

bool get_file_name_from_handle(HANDLE handle, std::string& out_filename)
{
    HANDLE file_map = CreateFileMapping(handle, NULL, PAGE_READONLY, NULL, NULL, NULL);
    if (!file_map)
        return false;

    void* map_view = MapViewOfFile(file_map, FILE_MAP_READ, NULL, NULL, 1);
    if (!map_view)
    {
        CloseHandle(file_map);
        return false;
    }

    CHAR found_file_name[MAX_PATH];
    if (!GetMappedFileName(GetCurrentProcess(), map_view, found_file_name, MAX_PATH))
    {
        UnmapViewOfFile(map_view);
        CloseHandle(file_map);
        return false;
    }

    out_filename = found_file_name;

    UnmapViewOfFile(map_view);
    CloseHandle(file_map);
    return true;
}

bool list_process_handles(int process_id)
{
    int handle_list_size = 0x10000;

    PSYSTEM_HANDLE_INFORMATION handle_list;
    NTSTATUS status;

    while (1)
    {
        handle_list = (PSYSTEM_HANDLE_INFORMATION)malloc(handle_list_size);

        status = NtQuerySystemInformation(SystemHandleInformation, handle_list, handle_list_size, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            free(handle_list);
            handle_list = NULL;

            handle_list_size *= 2;

            PSYSTEM_HANDLE_INFORMATION new_handle_list = (PSYSTEM_HANDLE_INFORMATION)malloc(handle_list_size);
            if (!new_handle_list)
                return false;

            handle_list = new_handle_list;
        }
        else
        {
            break;
        }
    }

    if (!handle_list || !NT_SUCCESS(status))
    {
        std::cout << ERROR << "NtQuerySystemInformation failed" << std::endl;
        return false;
    }

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (!process_handle)
    {
        std::cout << ERROR << "OpenProcess failed" << std::endl;
        return false;
    }

    std::cout << INFO << "Handle count: 0x" << std::hex << handle_list->HandleCount << std::endl;

    for (ULONG i = 0; i < handle_list->HandleCount; i++)
    {
        SYSTEM_HANDLE* handle = &handle_list->Handles[i];
        if (handle->ProcessId != process_id)
            continue;

        HANDLE duplicated_handle = NULL;

        // Duplicate the handle so we can query it
        if (!NT_SUCCESS(NtDuplicateObject(process_handle, (HANDLE)handle->Handle, GetCurrentProcess(), &duplicated_handle, GENERIC_READ, 0, 0)))
            continue;

        // Query object (required to check handle type)
        POBJECT_TYPE_INFORMATION object_type_info = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(duplicated_handle, ObjectTypeInformation, object_type_info, 0x1000, NULL)) || !object_type_info)
        {
            free(object_type_info);
            CloseHandle(duplicated_handle);
            continue;
        }

        // Skip non-file handles
        if (wcscmp(object_type_info->Name.Buffer, L"File"))
        {
            free(object_type_info);
            CloseHandle(duplicated_handle);
            continue;
        }

        // Retrieve handle file name
        std::string handle_file_name;
        if (!get_file_name_from_handle(duplicated_handle, handle_file_name))
        {
            free(object_type_info);
            CloseHandle(duplicated_handle);
            continue;
        }

        std::cout << INFO << handle_file_name << std::endl;
        CloseHandle(duplicated_handle);
    }

    return true;
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << ERROR << "Invalid usage" << std::endl;
        std::cout << INFO << "Example: handle-lister.exe pid" << std::endl;
        std::cout << INFO << "Example: handle-lister.exe 2156" << std::endl;
        return -1;
    }
   
    list_process_handles(std::stoi(argv[1]));

    std::cout << INFO << "Press any key to exit" << std::endl;
    std::cin.get();
    return 0;
}
