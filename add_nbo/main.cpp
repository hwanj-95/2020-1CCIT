#include <iostream>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
using namespace std;

void usage() {
    printf("syntax: add_nbo <file1> <file2>\n");
    printf("sample: add_nbo a.bin c.bin\n");

}

uint32_t add_nbo(char* argv) {
    uint32_t scan; // fread
    uint32_t* change; // file read data
    FILE* file = fopen(argv,"rb"); // argv < file1 or file2
    if(file == NULL){
        printf("file open error\n");
        exit(1);
    }
    fread(&scan, sizeof(uint32_t), 1, file); // file read scan < file
    change = &scan;
    uint32_t send = ntohl(*change); // net byte > host byte
    fclose(file);
    return send; // return main add_nbo

}


int main(int argc, char* argv[]) {

    if (argc != 3) {
            usage();
            return -1;
         }

    uint32_t fileread1 = add_nbo(argv[1]); // file1
    uint32_t fileread2 = add_nbo(argv[2]); // file2
    uint32_t total = fileread1 + fileread2;

    printf("%d(0x%04x) + %d(0x%04x) = %d(0x%04x)\n",fileread1, fileread1, fileread2, fileread2, total,total);

}


