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
  PDL_DEBUG(__VA_ARGS__);                                                      \
  return 0;

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
int proxify_dll(void *output, void *input, int flags) {
  PIMAGE_DOS_HEADER output_dos;
  PIMAGE_DOS_HEADER input_dos;
  PIMAGE_OPTIONAL_HEADER output_pe;
  PIMAGE_OPTIONAL_HEADER input_pe;

  //check malware image
  output_dos = (PIMAGE_DOS_HEADER)output;
  if (output_dos->e_magic == IMAGE_DOS_SIGNATURE) {
    output_pe = (PIMAGE_OPTIONAL_HEADER)((BYTE *)output + output_dos->e_lfanew);
    if (output_pe->Magic != IMAGE_NT_SIGNATURE) {
      PDL_ERROR("! Malware not a PE image\n")
    }
  } else {
    PDL_ERROR("! Malware not a MZ image\n")
  }

  //check input image
  input_dos = (PIMAGE_DOS_HEADER)input;
  if (input_dos->e_magic == IMAGE_DOS_SIGNATURE) {
    input_pe = (PIMAGE_OPTIONAL_HEADER)((BYTE *)input + input_dos->e_lfanew);
    if (input_pe->Magic != IMAGE_NT_SIGNATURE) {
      PDL_ERROR("! DLL not a PE image\n")
    }
  } else {
    PDL_ERROR("! DLL not a MZ image\n")
  }

  //###
  return 0;
}
