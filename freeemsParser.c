/* FreeEMS - the open source engine management system
 *
 * Copyright 2009 Sean Keys
 *
 * This file is part of the FreeEMS project.
 *
 * FreeEMS software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * FreeEMS software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any FreeEMS software.  If not, see http://www.gnu.org/licenses/
 *
 * We ask that if you make any changes to this file you email them upstream to
 * us at admin(at)diyefi(dot)org or, even better, fork the code on github.com!
 *
 * Thank you for choosing FreeEMS to run your engine!
 */
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
/* Special byte definitions */
#define ESCAPE_BYTE	0xBB
#define START_BYTE	0xAA
#define STOP_BYTE	0xCC
#define ESCAPED_ESCAPE_BYTE		0x44
#define ESCAPED_START_BYTE		0x55
#define ESCAPED_STOP_BYTE		0x33
#define OUT_FILE_EXTENSION	    ".csv"
#define END_OF_STRING           0x00
#define MEGABYTE                0x100000 /* 1 megabyte in hex */
#define DEFAULT_FILE_IN         "test.bin"
#define DEFAULT_FILE_OUT        "testOut.csv"
#define CONFIGF_FILE            "config"

/* #########################  EXAMPLE PACKET START thx Aaron###########################
 *
 * AA 08 01 91 00 60 82 68..................
 *  AA = Start
 *  08 = Header flags (08 = hasLength, 4th bit)
 *  01 91 = Payload ID (401)
 *  00 60 = Length of payload (96) <- because we have the hasLength flag... 96 bytes of payload ...
 *  xx = Checksum
 *  CC = END
 */

int main(int argc, char *argv[]){

	/*  Generic protocol constants */
	const char SZEROS = 0x00; /* No bits = 0 */
	const char SBIT0 = 0x01; /* 1st bit = 1 */
	const char SBIT1 = 0x02; /* 2nd bit = 2 */
	const char SBIT2 = 0x04; /* 3rd bit = 4 */
	const char SBIT3 = 0x08; /* 4th bit = 8 */
	const char SBIT4 = 0x10; /* 5th bit = 16 */
	const char SBIT5 = 0x20; /* 6th bit = 32 */
	const char SBIT6 = 0x40; /* 7th bit = 64 */
	const char SBIT7 = 0x80; /* 8th bit = 128 */

	/* statics */
	static packetBuffer[MEGABYTE];

	/* Statistic collection variables */
	/* TODO move to struct */
	unsigned int packets = 0;
	unsigned int charsDropped = 0;
	unsigned int badChecksums = 0;
	unsigned int goodChecksums = 0;
	unsigned int startsInsidePacket = 0;
	unsigned int totalFalseStartLost = 0;
	unsigned int doubleStartByteOccurances = 0;
	unsigned int strayDataBytesOccurances = 0;
	unsigned int escapeBytesFound = 0;
	unsigned int escapedStopBytesFound = 0;
	unsigned int escapedStartBytesFound = 0;
	unsigned int escapedEscapeBytesFound = 0;
	unsigned int escapePairMismatches = 0;
	unsigned int expectedPacketLength = 0;
	unsigned int calculatedPacketLength = 0;
	unsigned int packetPosition = 0;

	/* Loop and state variables */
	char currentCharacter = 0;
	char insidePacket = 0;
	unsigned int currentCharacterCount = 0;
	unsigned int packetCount = 0;
	unsigned int inFileLength = 0;

	FILE *inputFile;
	FILE *outputFile;
    char inputFileName[100];
    char outputFileName[100];

	if(argc == 1){
		char c;
		printf("\n No Input File Specified e.g. (FreeEMSParser log.bin)");
		printf("\n Opening Default File test.bin, Press Enter To Continue");
		c = getchar();
		sprintf(inputFileName,"%s",DEFAULT_FILE_IN);
		sprintf(outputFileName,"%s",DEFAULT_FILE_OUT);

	}else if(argc == 2){  /* first arg is infile name */
		strcpy(inputFileName,argv[1]);
	}
	inputFile = fopen(inputFileName,"rb");
	outputFile = fopen(outputFileName,"w");
	if (inputFile == NULL){
		printf("\nError opening inputFile %s",inputFileName);
		return 1;
	}
	if (outputFile == NULL){
		printf("\nError opening outputFile %s",outputFileName);
		return 2;
	}
	fseek(inputFile,0L,SEEK_END);
	inFileLength = ftell(inputFile);
	rewind(inputFile);

	while (currentCharacterCount < inFileLength ){
		currentCharacter = fgetc(inputFile);
		currentCharacterCount++;
		if (currentCharacter == START_BYTE){
			insidePacket = 1;
			packetPosition = 0;

		}else if (insidePacket && (packetPosition == 0)){
			packetPosition++;
			char headerID = currentCharacter;
		}

	}

	return 0;
}

