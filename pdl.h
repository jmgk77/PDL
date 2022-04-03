//
//
//     `7MM"""Mq.`7MM"""Yb. `7MMF'
//       MM   `MM. MM    `Yb. MM
//       MM   ,M9  MM     `Mb MM
//       MMmmdM9   MM      MM MM
//       MM        MM     ,MP MM      ,
//       MM        MM    ,dP' MM     ,M
//     .JMML.    .JMMmmmdP' .JMMmmmmMMM
//
//
// (c) jmgk 2022

#pragma once

#include <cstdio>

#include <windows.h>
#include <winnt.h>

#define PDL_FLAG_VERBOSE 1

#define DBG_BRK asm("int $3");

#define PDL_INFO(...)                                                          \
  if (flags & PDL_FLAG_VERBOSE)                                                \
    printf(__VA_ARGS__);
#define PDL_DEBUG(...) printf(__VA_ARGS__);
#define PDL_ERROR(...)                                                         \
  printf(__VA_ARGS__);                                                         \
  return 0;

class pdl {
private:
  //
  void *rva2raw(PIMAGE_DOS_HEADER map, int RVA) {
    PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((BYTE *)map + map->e_lfanew);
    PIMAGE_SECTION_HEADER section_table =
        (PIMAGE_SECTION_HEADER)((BYTE *)pe + sizeof(IMAGE_NT_HEADERS));
    for (int section = 0; section < pe->FileHeader.NumberOfSections;
         section++) {
      int start = section_table[section].VirtualAddress;
      if ((RVA >= start) &&
          (RVA <= start + section_table[section].SizeOfRawData)) {
        return (void *)((RVA - start) +
                        section_table[section].PointerToRawData + (BYTE *)map);
      }
    }
    return 0;
  }

  //
  void dump_export_table(PIMAGE_DOS_HEADER map) {
    PIMAGE_NT_HEADERS map_pe =
        (PIMAGE_NT_HEADERS)((BYTE *)map + map->e_lfanew);

    //parse export_tables
    PIMAGE_EXPORT_DIRECTORY export_table = (PIMAGE_EXPORT_DIRECTORY)rva2raw(
        map,
        map_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress);

    if (export_table) {

      PDL_DEBUG("IMAGE_EXPORT_DIRECTORY\n");
      PDL_DEBUG("\tDWORD Characteristics\t0x%x\n",
                export_table->Characteristics)
      PDL_DEBUG("\tDWORD TimeDateStamp\t0x%x\n", export_table->TimeDateStamp)
      PDL_DEBUG("\tWORD MajorVersion\t0x%x\n", export_table->MajorVersion)
      PDL_DEBUG("\tWORD MinorVersion\t0x%x\n", export_table->MinorVersion)
      PDL_DEBUG("\tDWORD Name\t0x%x (%s)\n", export_table->Name,
                (char *)rva2raw(map, export_table->Name))
      PDL_DEBUG("\tDWORD Base\t0x%x\n", export_table->Base)
      PDL_DEBUG("\tDWORD NumberOfFunctions\t0x%x\n",
                export_table->NumberOfFunctions)
      PDL_DEBUG("\tDWORD NumberOfNames\t0x%x\n", export_table->NumberOfNames)
      PDL_DEBUG("\tDWORD AddressOfFunctions\t0x%x\n",
                export_table->AddressOfFunctions)
      PDL_DEBUG("\tDWORD AddressOfNames\t0x%x\n", export_table->AddressOfNames)
      PDL_DEBUG("\tDWORD AddressOfNameOrdinals\t0x%x\n",
                export_table->AddressOfNameOrdinals)

      if (export_table->NumberOfFunctions) {
        PDL_DEBUG("export_tableS\n")
        WORD *ordinal =
            (WORD *)rva2raw(map, export_table->AddressOfNameOrdinals);
        DWORD *name = (DWORD *)rva2raw(map, export_table->AddressOfNames);
        DWORD *function =
            (DWORD *)rva2raw(map, export_table->AddressOfFunctions);
        for (int c = 0; c < export_table->NumberOfFunctions; c++) {
          PDL_DEBUG("\t%d\t%s\t(0x%x)\n", *ordinal++, rva2raw(map, *name),
                    *function)
          //if *function is between export_table.VirtualAddress and
          //export_table.VirtualAddress + export_table.Size then is FORWARDED
          if ((*function >= map_pe->OptionalHeader
                                .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                .VirtualAddress) &&
              (*function < map_pe->OptionalHeader
                                   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                   .VirtualAddress +
                               map_pe->OptionalHeader
                                   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                   .Size)) {
            PDL_DEBUG("\t\t\t\tFORWARDED\n")
          }
          name++;
          function++;
        }
      }
    }
  }

  //
  bool check_pe(PIMAGE_DOS_HEADER map) {
    if (map->e_magic == IMAGE_DOS_SIGNATURE) {
      PIMAGE_NT_HEADERS map_pe =
          (PIMAGE_NT_HEADERS)((BYTE *)map + map->e_lfanew);
      if (map_pe->Signature == IMAGE_NT_SIGNATURE) {
        return true;
      }
    }
    return false;
  }

public:
  //
  int proxify_dll(void *fake_dll, void *original_dll, int flags) {
    PDL_INFO("! Processing...\n")

    PIMAGE_DOS_HEADER input = (PIMAGE_DOS_HEADER)original_dll;
    PIMAGE_DOS_HEADER output = (PIMAGE_DOS_HEADER)fake_dll;

    //check file images
    if (!check_pe(output)) {
      PDL_ERROR("! FAKEDLL not a valid file\n")
    }

    if (!check_pe(input)) {
      PDL_ERROR("! ORIGINALDLL not a valid file\n")
    }

    PDL_INFO("! Images are valid...\n")

    dump_export_table(input);
    dump_export_table(output);

    //###
    //###

    return 0;
  }

} PDL;
