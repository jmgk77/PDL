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
#include <string>
#include <vector>

#include <windows.h>
#include <winnt.h>

using namespace std;

#define PDL_FLAG_VERBOSE 1
#define PDL_FLAG_REUSE 1 << 1
#define PDL_FLAG_CREATE 1 << 2

#define DBG_BRK asm("int $3");

#define PDL_INFO(...)                                                          \
  if (flags & PDL_FLAG_VERBOSE)                                                \
    printf(__VA_ARGS__);
#define PDL_DEBUG(...) printf(__VA_ARGS__);
#define PDL_ERROR(...)                                                         \
  printf(__VA_ARGS__);                                                         \
  return 0;

#define ALIGN(x, a) __ALIGN_MASK(x, (a)-1)
#define __ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))

#define EXPORT_FORWARD 1
#define EXPORT_ALREADY_FORWARDED 2
#define EXPORT_LOCAL 3

struct export_list_item {
  int type;
  WORD ordinal;
  DWORD address;
  string name;
};

class pdl {
private:
  int flags;
  const char *dllname;
  const char *newdll;
  const char *newsection;
  int dllbase;
  vector<export_list_item> export_list;

  //!!!convert a in-memory pointer to a file offset
  void *rva2raw(PIMAGE_DOS_HEADER map, int RVA) {
    PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((BYTE *)map + map->e_lfanew);
    PIMAGE_SECTION_HEADER section_table =
        (PIMAGE_SECTION_HEADER)((BYTE *)pe + sizeof(IMAGE_NT_HEADERS));
    //for each section...
    for (int section = 0; section < pe->FileHeader.NumberOfSections;
         section++) {
      int start = section_table[section].VirtualAddress;
      //RVA inside it?
      if ((RVA >= start) &&
          (RVA <= start + section_table[section].SizeOfRawData)) {
        //return phys
        return (void *)((RVA - start) +
                        section_table[section].PointerToRawData + (BYTE *)map);
      }
    }
    return 0;
  }

  //!!!dump info about export table (debug)
  void dump_export_table(PIMAGE_DOS_HEADER map) {
    PIMAGE_NT_HEADERS map_pe = (PIMAGE_NT_HEADERS)((BYTE *)map + map->e_lfanew);

    //parse export_tables
    PIMAGE_EXPORT_DIRECTORY export_table = (PIMAGE_EXPORT_DIRECTORY)rva2raw(
        map, map_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
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
          PDL_DEBUG("\t%d\t%s\t(0x%x)\n", *ordinal++, rva2raw(map, *name++),
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
          function++;
        }
      }
    }
  }

  //!!!create a new section for exports
  bool create_export_section(PIMAGE_DOS_HEADER map, int newsize) {
    PIMAGE_NT_HEADERS map_pe = (PIMAGE_NT_HEADERS)((BYTE *)map + map->e_lfanew);
    PIMAGE_SECTION_HEADER section_table =
        (PIMAGE_SECTION_HEADER)((BYTE *)map_pe + sizeof(IMAGE_NT_HEADERS));
    //check if enought size
    if ((map->e_lfanew + sizeof(IMAGE_NT_HEADERS) +
         (((map_pe->FileHeader.NumberOfSections) + 1) *
          sizeof(IMAGE_SECTION_HEADER))) > section_table[0].PointerToRawData) {
      return false;
    }
    //create new section
    int section = map_pe->FileHeader.NumberOfSections++;
    memcpy(section_table[section].Name, newsection, strlen(newsection));
    section_table[section].VirtualAddress =
        ALIGN(section_table[section - 1].VirtualAddress +
                  section_table[section - 1].Misc.VirtualSize,
              map_pe->OptionalHeader.SectionAlignment);
    section_table[section].PointerToRawData =
        section_table[section - 1].PointerToRawData +
        section_table[section - 1].SizeOfRawData;

    section_table[section].Misc.VirtualSize = newsize;
    section_table[section].SizeOfRawData = newsize;

    section_table[section].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA +
                                             IMAGE_SCN_ALIGN_4BYTES +
                                             IMAGE_SCN_MEM_READ;

    section_table[section].SizeOfRawData =
        ALIGN(newsize, map_pe->OptionalHeader.FileAlignment);

    //export dir
    map_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        .VirtualAddress = section_table[section].VirtualAddress;
    map_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size =
        newsize;

    //fix
    map_pe->OptionalHeader.SizeOfInitializedData +=
        section_table[section].SizeOfRawData;

    return true;
  }

  //!!!reuse existing export section
  bool reuse_export_section(PIMAGE_DOS_HEADER map, int newsize) {
    PIMAGE_NT_HEADERS map_pe = (PIMAGE_NT_HEADERS)((BYTE *)map + map->e_lfanew);

    int export_RVA =
        map_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress;
    int export_size =
        map_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    PIMAGE_SECTION_HEADER section_table =
        (PIMAGE_SECTION_HEADER)((BYTE *)map_pe + sizeof(IMAGE_NT_HEADERS));
    for (int section = 0; section < map_pe->FileHeader.NumberOfSections;
         section++) {
      int start = section_table[section].VirtualAddress;
      //section has the current export table?
      if ((export_RVA >= start) &&
          (export_RVA <= start + section_table[section].SizeOfRawData)) {
        //if last section
        if (((section == (map_pe->FileHeader.NumberOfSections - 1)) ||
             //or there's space till next section
             ((section_table[section + 1].PointerToRawData -
               section_table[section].PointerToRawData) > newsize)) &&
            //and only export table reside in this section
            (section_table[section].Misc.VirtualSize == export_size))

        {
          //fix section
          section_table[section].Misc.VirtualSize = newsize;
          //fix export directory
          map_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
              .VirtualAddress = section_table[section].VirtualAddress;
          map_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
              .Size = newsize;
          //fix pe header
          map_pe->OptionalHeader.SizeOfInitializedData -= export_size;
          map_pe->OptionalHeader.SizeOfInitializedData += newsize;
          return true;
        }
      }
    }
    return false;
  }

  //!!!convert export data to internal struct
  void process_export_table(PIMAGE_DOS_HEADER map, int flag) {
    PIMAGE_NT_HEADERS map_pe = (PIMAGE_NT_HEADERS)((BYTE *)map + map->e_lfanew);

    //parse export_tables
    PIMAGE_EXPORT_DIRECTORY export_table = (PIMAGE_EXPORT_DIRECTORY)rva2raw(
        map, map_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                 .VirtualAddress);

    if (export_table) {
      //save name & base
      dllbase = export_table->Base;

      if (export_table->NumberOfFunctions) {
        //3 tables
        WORD *ordinal =
            (WORD *)rva2raw(map, export_table->AddressOfNameOrdinals);
        DWORD *name = (DWORD *)rva2raw(map, export_table->AddressOfNames);
        DWORD *function =
            (DWORD *)rva2raw(map, export_table->AddressOfFunctions);
        for (int c = 0; c < export_table->NumberOfFunctions; c++) {

          export_list_item exp;

          //convert to our format
          exp.ordinal = *ordinal;
          exp.address = (flag & EXPORT_LOCAL) ? *function : 0;
          char *fname = (char *)rva2raw(map, *name);
          exp.name = string(fname);

          exp.type = flag;

          if ((*function >= map_pe->OptionalHeader
                                .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                .VirtualAddress) &&
              (*function < map_pe->OptionalHeader
                                   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                   .VirtualAddress +
                               map_pe->OptionalHeader
                                   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                   .Size)) {
            exp.type = EXPORT_ALREADY_FORWARDED;
            char *fname = (char *)rva2raw(map, *function);
            exp.name = string(fname);
            exp.address = -1;
          }

          ordinal++;
          name++;
          function++;

          export_list.push_back(exp);
        }
      }
    }
  }

  //!!!check exe for validity
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

  //!!!parse internal export data and create pe export info
  void create_export_data(PIMAGE_DOS_HEADER map, int _RVA, const char *newdll) {
    BYTE *ptr = (BYTE *)rva2raw(map, _RVA);
    int rva = _RVA;
    //init IMAGE_EXPORT_DIRECTORY
    PIMAGE_EXPORT_DIRECTORY export_table = (PIMAGE_EXPORT_DIRECTORY)ptr;
    memset(ptr, 0, sizeof(IMAGE_EXPORT_DIRECTORY));
    //copy name & base
    export_table->Base = dllbase;
    ptr += sizeof(IMAGE_EXPORT_DIRECTORY);
    rva += sizeof(IMAGE_EXPORT_DIRECTORY);
    export_table->Name = rva;
    strcpy((char *)ptr, dllname);
    ptr += ALIGN(strlen(dllname) + 1, 4);
    rva += ALIGN(strlen(dllname) + 1, 4);
    //ptr and rva of 3 lists
    DWORD *functions_ptr = (DWORD *)ptr;
    int functions_rva = rva;
    //
    DWORD *names_ptr =
        (DWORD *)((BYTE *)functions_ptr + (export_list.size() * sizeof(DWORD)));
    int names_rva = (functions_rva + (export_list.size() * sizeof(DWORD)));
    //
    WORD *ordinals_ptr =
        (WORD *)((BYTE *)names_ptr + (export_list.size() * sizeof(DWORD)));
    int ordinals_rva = (names_rva + (export_list.size() * sizeof(DWORD)));
    //and names list area
    char *list_ptr =
        (char *)((BYTE *)ordinals_ptr + (export_list.size() * sizeof(WORD)));
    int list_rva = (ordinals_rva + (export_list.size() * sizeof(WORD)));
    //save to IMAGE_EXPORT_DIRECTORY
    export_table->NumberOfFunctions = export_list.size();
    export_table->AddressOfFunctions = functions_rva;
    export_table->AddressOfNames = names_rva;
    export_table->AddressOfNameOrdinals = ordinals_rva;
    //for each entry in internal struct...
    for (auto it = begin(export_list); it != end(export_list); ++it) {
      *functions_ptr = it->address;
      *ordinals_ptr = it->ordinal;
      if (!(it->name).empty()) {
        if (it->type == EXPORT_FORWARD) {
          //forwarded? copy dllname and set api to it
          strcpy(list_ptr, newdll);
          *functions_ptr = list_rva;
          list_ptr += strlen(newdll);
          *list_ptr++ = '.';
          list_rva += strlen(newdll) + 1;
          //and then copy name
        }
        if ((it->type == EXPORT_LOCAL) || (it->type == EXPORT_FORWARD)) {
          //copy name (api already in place)
          strcpy(list_ptr, (it->name).c_str());
          *names_ptr = list_rva;
          list_ptr += (it->name).length() + 1;
          list_rva += (it->name).length() + 1;
        }
        if (it->type == EXPORT_ALREADY_FORWARDED) {
          //already forwarded
          strcpy(list_ptr, (it->name).c_str());
          //point both api and name to string
          *functions_ptr = list_rva;
          *names_ptr = list_rva;
          list_ptr += (it->name).length() + 1;
          list_rva += (it->name).length() + 1;
          //but adjust name to point after the dot
          *names_ptr += (it->name).find('.') + 1;
        }
        export_table->NumberOfNames++;
      }

      //next item
      functions_ptr++;
      names_ptr++;
      ordinals_ptr++;
    }
  }

  int calc_checksum(PIMAGE_DOS_HEADER map, int size) {
    DWORD *base = (DWORD *)map;
    unsigned long long checksum = 0;
    unsigned long long limit = 0xFFFFFFFF;
    limit++;
    int checksum_offset =
        (map->e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) + 64) / 4;
    //loop file
    for (long long i = 0; i < (size / 4); i++) {
      unsigned long dw = base[i];
      //skip existing checksum
      if (i != checksum_offset) {
        //calculate checksum
        checksum = (checksum & 0xffffffff) + dw + (checksum >> 32);
        if (checksum > limit) {
          checksum = (checksum & 0xffffffff) + (checksum >> 32);
        }
      }
    }
    //finish checksum
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum) + (checksum >> 16);
    checksum = checksum & 0xffff;
    checksum += size;
    PDL_INFO("! Checksum: 0x%08x\n", checksum);
    return checksum;
  }

public:
  //proxify_dll()
  //  params->
  //    fake_dll     : mmap of our proxy dll
  //    original_dll : mmap of dll to proxify
  //    _dllname     : name of the dll to proxify (with ".DLL" ending)
  //    _newdll      : name we will rename the proxified dll (without ".DLL" ending)
  //    __newsection : name of new section
  //    f            : flags
  //                      PDL_FLAG_VERBOSE  -> show debug info
  //                      PDL_FLAG_REUSE    -> reuse existing export section
  //                      PDL_FLAG_CREATE   -> create new export section
  //  return->
  //                 : new size, or 0 if error
  int proxify_dll(void *fake_dll, void *original_dll, const char *_dllname,
                  const char *_newdll, const char *_newsection, int f) {
    PDL_INFO("! Processing...\n")
    flags = f;

    //copy data
    dllname = _dllname;
    newdll = _newdll;
    newsection = _newsection;

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

    //process output exports
    process_export_table(output, EXPORT_LOCAL);
    //process input exports
    process_export_table(input, EXPORT_FORWARD);

    //calc new export size
    int export_size = sizeof(IMAGE_EXPORT_DIRECTORY);
    export_size += strlen(dllname);
    export_size +=
        export_list.size() * (sizeof(DWORD) + sizeof(DWORD) + sizeof(WORD));

    PDL_INFO("! Exports found:\n")
    for (auto it = begin(export_list); it != end(export_list); ++it) {
      export_size += (it->name).length();
      if (it->type & EXPORT_FORWARD) {
        export_size += strlen(newdll) + 1;
      }
      PDL_INFO("0x%02x\t%s (0x%08x)\t%s\n", it->ordinal, (it->name).c_str(),
               it->address,
               (it->type == EXPORT_LOCAL)
                   ? "LOCAL"
                   : (it->type == EXPORT_FORWARD) ? "FORWARD" : "ALREADY");
    }
    PDL_INFO("! New export info size: %d\n", export_size);

    //reuse export section
    PDL_INFO("! Patching export data...\n")
    if (!reuse_export_section(output, export_size) ||
        (!(flags & PDL_FLAG_REUSE))) {
      PDL_INFO("! Cant reuse export section! Creating new export section...\n")
      //create new export section
      if ((!create_export_section(output, export_size)) ||
          (!(flags & PDL_FLAG_CREATE))) {
        PDL_ERROR("! Cant create new export section... Error\n")
        return 0;
      }
    }

    //rebuild exports
    PIMAGE_NT_HEADERS pe =
        (PIMAGE_NT_HEADERS)((BYTE *)output + output->e_lfanew);
    int export_RVA =
        pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress;
    create_export_data(output, export_RVA, newdll);

    //dump_export_table(output);

    //calculate DLL size
    PIMAGE_SECTION_HEADER section_table =
        (PIMAGE_SECTION_HEADER)((BYTE *)pe + sizeof(IMAGE_NT_HEADERS));
    int size =
        section_table[pe->FileHeader.NumberOfSections - 1].PointerToRawData;
    size += section_table[pe->FileHeader.NumberOfSections - 1].SizeOfRawData;
    PDL_INFO("! Final DLL size: %d\n", size);

    //fix checksum
    pe->OptionalHeader.CheckSum = calc_checksum(output, size);

    //return size;
    return 0;
  }
} PDL;
