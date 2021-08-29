
#include <iostream>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include "Signature.h"
#pragma warning (disable : 4996)

wchar_t* NewWideString(const wchar_t* Data) {
    int Length = wcslen(Data) + 1;
    int StringSize = Length * sizeof(wchar_t);
    int StructSize = 16 + StringSize;

    char* Struct = (char*)malloc(StructSize);
    memcpy(Struct, &Length, sizeof(int));
    memcpy(Struct + 16, Data, StringSize);

    return (wchar_t*)(Struct + 16);
}

wchar_t* NewWideString(const char* Data) {
    int Length = strlen(Data) + 1;
    wchar_t* WideString = new wchar_t(Length);
    mbstowcs(WideString, Data, Length);
    return NewWideString(WideString);
}

struct HexWorkshopLicense
{
    wchar_t* ProductName;
    wchar_t* ProductID;
    wchar_t* ProductKey;
    wchar_t* LicenseeName;
    wchar_t* LicenseeCompany;
    wchar_t* Granted;
    int EvaluationPeriod;
    int EvaluationVersion;
    wchar_t* MaintenanceExpiration;
    wchar_t* LicenseName;
    wchar_t* LicenseEmail;
    DWORD RegistrationID;
    DWORD CustomerID;
    DWORD ActivationID;
    int Pad1;
    wchar_t* Signature;
    wchar_t* Generator;
    wchar_t* ClientInfo;
};

int main()
{
    HMODULE LicensingDLL = LoadLibraryA("BPSRegWD64.dll");

    if (LicensingDLL == NULL) {
        printf("Failed to load BPSRegWD64.dll, get it from Hex Workshop install directory\n");
        getchar();
        return 0;
    }

    // These have to be heap allocated because of the weird length var and padding above the data pointer.
    // They'll all be destroyed when the generator inevitably closes anyway so it doesn't really matter.
    HexWorkshopLicense License;
    License.ProductName = NewWideString(L"Hex Workshop");
    License.ProductID = NewWideString(L"4");
    License.ProductKey = NewWideString(L"");
    License.LicenseeName = NewWideString(L"");
    License.LicenseeCompany = NewWideString(L"");
    License.Granted = NewWideString(L"2099-1-1");
    License.EvaluationPeriod = 9999;
    License.EvaluationVersion = 13;
    License.MaintenanceExpiration = NewWideString(L"2099-1-1");
    License.LicenseName = NewWideString(L"");
    License.LicenseEmail = NewWideString(L"");
    License.RegistrationID = 0;
    License.CustomerID = 0;
    License.ActivationID = 0;
    License.Pad1 = 0;
    License.Signature = NewWideString(L"");
    License.Generator = NewWideString(L"BPSInst v2");
    License.ClientInfo = NewWideString(L"");

    printf("Name: ");
    std::wstring Name;
    std::getline(std::wcin, Name);

    printf("Company: ");
    std::wstring Company;
    std::getline(std::wcin, Company);

    License.LicenseeName = NewWideString(Name.c_str());
    License.LicenseeCompany = NewWideString(Company.c_str());

    const char* const GenerateSimplifiedLicenseSig = "40 55 56 41 54 48 8B EC 48 83 EC 30 48 C7 45 ? ? ? ? ? 48 89 5C 24 ? 48 8B F2 48 8B D9 83 65 20 00 48 8D 4D 20 FF 15 ? ? ? ? 90 48 8B D3 48 8D 4D 20 FF 15 ? ? ? ? 4C 8D 25";
    static auto GenerateSimplifiedLicense = Signature::FindPatternInModule<char**(__fastcall*)(HexWorkshopLicense* License, char* Buffer)>(LicensingDLL, GenerateSimplifiedLicenseSig);

    if (GenerateSimplifiedLicense == NULL) {
        printf("Failed to scan for generate simplified license function\n");
        getchar();
        return 0;
    }

    char Buffer[8];
    char* SimplifiedLicense = *GenerateSimplifiedLicense(&License, Buffer);
    printf("Generated simplified license (%s)\n", SimplifiedLicense);

    const char* const GenerateSignatureSig = "40 55 53 56 57 41 54 41 55 41 56 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 C7 44 24 ? ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 63 F0 48 8B FA 4C 8B F1 48 89 4C 24 ? 83 64 24 ? ? 48 8D 15";
    static auto GenerateSignature = Signature::FindPatternInModule<char**(__fastcall*)(char* Buffer, char* SimplifiedLicense, int SimplifiedLicenseLen)>(LicensingDLL, GenerateSignatureSig);

    if (GenerateSignature == NULL) {
        printf("Failed to scan for generate signature function\n");
        getchar();
        return 0;
    }

    std::string Signature = *GenerateSignature(Buffer, SimplifiedLicense, strlen(SimplifiedLicense));
    License.Signature = NewWideString(Signature.c_str());
    printf("Generated signature (%s)\n", Signature.substr(0, Signature.length() - 1).c_str());

    const char* const GenerateWritableLicenseSig = "48 89 54 24 ? 55 53 56 57 41 54 41 55 41 57 48 8B EC 48 83 EC 30 48 C7 45 ? ? ? ? ? 48 8B DA 48 8B F9 83 65 40 00 48 8B CA FF 15 ? ? ? ? C7 45";
    static auto GenerateWritableLicense = Signature::FindPatternInModule<wchar_t**(__fastcall*)(HexWorkshopLicense* License, char* Buffer)>(LicensingDLL, GenerateWritableLicenseSig);

    if (GenerateWritableLicense == NULL) {
        printf("Failed to scan for generate writable license function\n");
        getchar();
        return 0;
    }

    std::wstring WideWritableLicense = *GenerateWritableLicense(&License, Buffer);
    std::string WritableLicense = std::string(WideWritableLicense.begin(), WideWritableLicense.end());
    printf("Generated writable license\n");
    wchar_t CurrentPath[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, CurrentPath);
    std::wstring LicensePath = CurrentPath;
    LicensePath += L"\\Hex Workshop{EVAL}.lic";

    FILE* File = _wfopen(LicensePath.c_str(), L"w");
    if (File == NULL) {
        printf("Error occured while writing file\n");
        return 0;
    }
    fwrite(WritableLicense.c_str(), sizeof(char), WritableLicense.length(), File);
    fclose(File);

    printf("Done! Wrote license to '%ws'.\n", LicensePath.c_str());
    getchar();
}
