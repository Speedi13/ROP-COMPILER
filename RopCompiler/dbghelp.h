#pragma once
//code from: https://github.com/Speedi13/Custom-GetProcAddress-and-GetModuleHandle-and-more

//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Locates the IMAGE_NT_HEADERS structure in a PE image and returns a pointer to the data
/// </summary>
/// <param name="Base">The base address of an image that is mapped into memory by a call to the MapViewOfFile function</param>
/// <returns>If the function succeeds, the return value is a pointer to an IMAGE_NT_HEADERS structure</returns>
IMAGE_NT_HEADERS* WINAPI ImageNtHeader( _In_ const PVOID Base );

//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Locates a relative virtual address (RVA) within the image header of a file that is mapped as a file and returns the virtual address of the corresponding byte in the file.
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function</param>
/// <param name="Base">The base address of an image that is mapped into memory through a call to the MapViewOfFile / ReadFile function</param>
/// <param name="Rva">The relative virtual address to be located</param>
/// <returns>If the function succeeds, the return value is the virtual address in the mapped file</returns>
PVOID WINAPI ImageRvaToVa( const IMAGE_NT_HEADERS* NtHeaders, const void* Base, const DWORD Rva);

/// <summary>
/// Locates a relative virtual address (RVA) within the image header of a file that is mapped as a file and returns a pointer to the section table entry for that RVA
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function.</param>
/// <param name="Base">This parameter is reserved</param>
/// <param name="Rva">The relative virtual address to be located</param>
/// <returns>If the function succeeds, the return value is a pointer to an IMAGE_SECTION_HEADER structure</returns>
IMAGE_SECTION_HEADER* WINAPI ImageRvaToSection( const IMAGE_NT_HEADERS* NtHeaders, const PVOID Base, const ULONG Rva);

//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Retrieves the address of an exported function inside the specified module
/// </summary>
/// <param name="hModule">Address of the module</param>
/// <param name="lpProcName">Name of the exported procedure</param>
/// <param name="MappedAsImage">Is the module mapped or a raw file? (TRUE / FALSE)</param>
/// <returns>returns the exported procedure address inside the specified module</returns>
FARPROC WINAPI GetProcAddressToLower( _In_ const HMODULE hModule, _In_ LPCSTR lpProcName, _In_ const BOOLEAN MappedAsImage );