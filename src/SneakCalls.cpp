#include "SneakCalls.hpp"
#include "PeHelper.hpp"

UINT_PTR SneakHelper::getNtdllBase()
{
    #if defined(_WIN64)
    PPEB pPeb = (PEB*)__readgsqword(0x60);
#else
    PEB* pPeb = (PEB*)__readfsdword(0x30);
#endif

    for(PLIST_ENTRY pEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink; pEntry != &pPeb->Ldr->InMemoryOrderModuleList; pEntry = pEntry->Flink)
    {
        PeImage image(((LDR_DATA_TABLE_ENTRY*)((UINT_PTR)pEntry - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)))->DllBase);

        if (!PeHelper::isValid(image))
            continue;

        if ((*(ULONG*)PeHelper::rvaToVA(image, PeHelper::getExportDirectory(image)->Name) | 0x20202020) != 'ldtn') 
            continue;

        if ((*(ULONG*)PeHelper::rvaToVA(image, (PeHelper::getExportDirectory(image)->Name + 4)) | 0x20202020) == 'ld.l') 
            return image.base;
    }

    return NULL;
}

UINT32 SneakHelper::hashToScn(UINT32 hash)
{
    PeImage ntdll((PVOID)getNtdllBase());

    if (!ntdll.base || !PeHelper::isValid(ntdll))
        return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = PeHelper::getExportDirectory(ntdll);

    PDWORD pFunctions = (PDWORD)PeHelper::rvaToVA(ntdll, pExportDirectory->AddressOfFunctions);
    PDWORD pNames = (PDWORD)PeHelper::rvaToVA(ntdll, pExportDirectory->AddressOfNames);
    PWORD pOrdinals = (PWORD)PeHelper::rvaToVA(ntdll, pExportDirectory->AddressOfNameOrdinals);

    DWORD pFunction = 0;
    
    for (int i = pExportDirectory->NumberOfNames - 1; i >= 0; i--)
    {
        PCHAR functionName = (PCHAR)PeHelper::rvaToVA(ntdll, pNames[i]);

        if (*(USHORT*)functionName == 'wZ' && SneakHelper::hash(functionName) == hash)
        {
            pFunction = pFunctions[pOrdinals[i]];
            break;
        }
    }

    if (!pFunction)
        return -1;

    DWORD syscallNumber = 0;

    for (int i = pExportDirectory->NumberOfNames - 1; i >= 0; i--)
    {
        PCHAR functionName = (PCHAR)PeHelper::rvaToVA(ntdll, pNames[i]);

        if (*(USHORT*)functionName == 'wZ' && pFunction > pFunctions[pOrdinals[i]])
            syscallNumber++;
    }

    return syscallNumber;
}