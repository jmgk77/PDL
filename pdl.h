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

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <windows.h>
#include <winnt.h>

#define PDL_FLAG_DEBUG 1

#define PDL_DEBUG(...)                                                         \
  if (flags & PDL_FLAG_DEBUG)                                                  \
    printf(__VA_ARGS__);
#define PDL_ERROR(...)                                                         \
  printf(__VA_ARGS__);                                                         \
  return 0;

//
//
//     .g8"""bgd `7MMF'        .g8""8q. `7MM"""Yp,      db      `7MMF'       .M"""bgd
//   .dP'     `M   MM        .dP'    `YM. MM    Yb     ;MM:       MM        ,MI    "Y
//   dM'       `   MM        dM'      `MM MM    dP    ,V^MM.      MM        `MMb.
//   MM            MM        MM        MM MM"""bg.   ,M  `MM      MM          `YMMNq.
//   MM.    `7MMF' MM      , MM.      ,MP MM    `Y   AbmmmqMA     MM      , .     `MM
//   `Mb.     MM   MM     ,M `Mb.    ,dP' MM    ,9  A'     VML    MM     ,M Mb     dM
//     `"bmmmdPY .JMMmmmmMMM   `"bmmd"' .JMMmmmd9 .AMA.   .AMMA..JMMmmmmMMM P"Ybmmd"
//
//
int flags;
PIMAGE_DOS_HEADER output;
PIMAGE_DOS_HEADER input;
PIMAGE_NT_HEADERS output_pe;
PIMAGE_NT_HEADERS input_pe;

//
//
//   `7MM"""Mq.`7MMF'   `7MF' db               `7MM"""Mq.        db `7MMF'     A     `7MF'
//     MM   `MM. `MA     ,V  ;MM:                MM   `MM.      ;MM:  `MA     ,MA     ,V
//     MM   ,M9   VM:   ,V  ,V^MM.     pd*"*b.   MM   ,M9      ,V^MM.  VM:   ,VVM:   ,V
//     MMmmdM9     MM.  M' ,M  `MM    (O)   j8   MMmmdM9      ,M  `MM   MM.  M' MM.  M'
//     MM  YM.     `MM A'  AbmmmqMA       ,;j9   MM  YM.      AbmmmqMA  `MM A'  `MM A'
//     MM   `Mb.    :MM;  A'     VML   ,-='      MM   `Mb.   A'     VML  :MM;    :MM;
//   .JMML. .JMM.    VF .AMA.   .AMMA.Ammmmmmm .JMML. .JMM..AMA.   .AMMA. VF      VF
//
//
void *pdl_rva2raw(PIMAGE_DOS_HEADER map, int RVA) {
  PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((BYTE *)map + map->e_lfanew);
  PIMAGE_SECTION_HEADER section_table =
      (PIMAGE_SECTION_HEADER)((BYTE *)pe + sizeof(IMAGE_NT_HEADERS));
  for (int section = 0; section < pe->FileHeader.NumberOfSections; section++) {
    int start = section_table[section].VirtualAddress;
    int end = start + section_table[section].VirtualAddress;
    if ((RVA >= start) && (RVA <= end)) {
      PDL_DEBUG("(RVA2RAW) 0x%x => 0x%x\n", RVA,
                (RVA - start) + section_table[section].PointerToRawData)
      return (RVA - start) + section_table[section].PointerToRawData + map;
    }
  }
  return 0;
}

//
//                                            ,,      ,...                 ,,    ,,    ,,     ....
//                                            db    .d' ""               `7MM  `7MM  `7MM   pd'  `bq
//                                                  dM`                    MM    MM    MM  6P      YA
//     `7MMpdMAo.`7Mb,od8 ,pW"Wq.`7M'   `MF'`7MM   mMMmm`7M'   `MF'   ,M""bMM    MM    MM 6M'      `Mb
//       MM   `Wb  MM' "'6W'   `Wb `VA ,V'    MM    MM    VA   ,V   ,AP    MM    MM    MM MN        8M
//       MM    M8  MM    8M     M8   XMX      MM    MM     VA ,V    8MI    MM    MM    MM MN        8M
//       MM   ,AP  MM    YA.   ,A9 ,V' VA.    MM    MM      VVV     `Mb    MM    MM    MM YM.      ,M9
//       MMbmmd' .JMML.   `Ybmd9'.AM.   .MA..JMML..JMML.    ,V       `Wbmd"MML..JMML..JMML.Mb      dM
//       MM                                                ,V                               Yq.  .pY
//     .JMML.                                           OOb"    mmmmmmm                       ``''
int proxify_dll(void *fake_dll, void *original_dll, int f) {

  flags = f;

  PDL_DEBUG("! Processing...\n")

  //check malware image
  output = (PIMAGE_DOS_HEADER)fake_dll;
  if (output->e_magic == IMAGE_DOS_SIGNATURE) {
    output_pe = (PIMAGE_NT_HEADERS)((BYTE *)fake_dll + output->e_lfanew);
    if (output_pe->Signature != IMAGE_NT_SIGNATURE) {
      PDL_ERROR("! FAKEDLL not a PE image\n")
    }
  } else {
    PDL_ERROR("! FAKEDLL not a MZ image\n")
  }

  //check original image
  input = (PIMAGE_DOS_HEADER)original_dll;
  if (input->e_magic == IMAGE_DOS_SIGNATURE) {
    input_pe = (PIMAGE_NT_HEADERS)((BYTE *)original_dll + input->e_lfanew);
    if (input_pe->Signature != IMAGE_NT_SIGNATURE) {
      PDL_ERROR("! ORIGINALDLL not a PE image\n")
    }
  } else {
    PDL_ERROR("! ORIGINALDLL not a MZ image\n")
  }

  PDL_DEBUG("! Images are valid...\n")

  //###
  //###
  //###

  return 0;
}
