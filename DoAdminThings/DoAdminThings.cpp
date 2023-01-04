#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include "sal.h"
#include "stdio.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

void WriteToFile(_In_z_ const char * szFolderAndFile)
{
    FILE* pFile{};
    fopen_s(&pFile, szFolderAndFile, "w");

    if (pFile == NULL) {
        perror("Could not open file");
        return;
    }

    const char* str = "This is a test.";
    fwrite(str, sizeof(char), strlen(str), pFile);

    fclose(pFile);
}

void WriteToProfileFolder()
{
    char profilePath[MAX_PATH];
    char filePath[MAX_PATH];

    if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, profilePath)))
        printf("Error getting user's profile folder!\n");
     
    sprintf_s(filePath, sizeof(filePath), "%s\\my_file.txt", profilePath);

    WriteToFile(filePath);
}

void WriteToRegistry(HKEY root)
{
    HKEY hKey;
    DWORD dwDisposition;

    LONG lResult = RegCreateKeyEx(
        root,
        L"SOFTWARE\\MikehowTest\\Foo",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        &dwDisposition
    );

    if (lResult == ERROR_SUCCESS)
    {
        DWORD dwType = REG_SZ;
        const wchar_t* wszValue = L"Hello, World!";
        DWORD cbData = sizeof(wchar_t) * (wcsnlen_s(wszValue, 32) + 1);

        RegSetValueEx(
            hKey,
            L"TestData",
            0,
            dwType,
            (const BYTE*)wszValue,
            cbData
        );

        RegCloseKey(hKey);
    }
}

void ReadCertFromStore(DWORD dwStore, _In_z_ const wchar_t *wszStore) 
{
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;

    // Open the machine store.
    hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM, 
        0,                     
        NULL,                  
        dwStore,
        wszStore);

    pCertContext = CertEnumCertificatesInStore(hStore, pCertContext);

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);
}

void AssertAPrivilege(_In_z_ const wchar_t *wszPriv) {

    HANDLE hToken;
    TOKEN_PRIVILEGES tkp{};

    // Open the process token for this process.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        printf("Error opening process token!\n");

    // Get the LUID for the debug privilege.
    if (!LookupPrivilegeValue(NULL, wszPriv, &tkp.Privileges[0].Luid))
        return;

    // Set the privilege for this process.
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL))
    {
        printf("Error adjusting token privileges!\n");
        return;
    }

    // Check if the privilege was successfully enabled.
    if (GetLastError() != ERROR_SUCCESS)
    {
        printf("Error enabling debug privilege!\n");
        return;
    }

    // The privilege has been successfully enabled.
    printf("Debug privilege enabled!\n");

    CloseHandle(hToken);
}

int main()
{
	/////////////////////////////////////////////////////////////////////////
	// These are all admin things
    printf("Writing to the Windows Folder");
    WriteToFile("c:\\windows\\system32\\test.txt");
	
	printf("Writing to the Program Files Folder");
    WriteToFile("c:\\program files\\test.txt");

    printf("Reading from System My certstore");
    ReadCertFromStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, L"My");

    printf("Writing to HKLM");
    WriteToRegistry(HKEY_LOCAL_MACHINE);

    printf("Asserting DEBUG priv");
    AssertAPrivilege(SE_DEBUG_NAME);

    /////////////////////////////////////////////////////////////////////////
    // These are non-admin things
    printf("Writing to profile folder");
    WriteToProfileFolder();

    printf("Reading from User's My certstore");
    ReadCertFromStore(CERT_SYSTEM_STORE_CURRENT_USER, L"My");
	
    printf("Writing to HKCU");
    WriteToRegistry(HKEY_CURRENT_USER);
}

