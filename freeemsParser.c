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
#define NORMAL                  "0x00"
#define SEEK                    "0x01"
#define NORMAL_RETURN           "0x02"
#define SEEK_RETURN             "0x03"

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
/* TODO move to header */
unsigned int getWordSpecial(unsigned int filePosition,unsigned int file, char option, unsigned int advance);
unsigned int getWord(unsigned int file);

int main(int argc, char *argv[]){

	/*  Generic protocol constants */
	const unsigned char SZEROS = 0x00; /* No bits = 0 */
	const unsigned char SBIT0 = 0x01; /* 1st bit = 1   Payload Type */
	const unsigned char SBIT1 = 0x02; /* 2nd bit = 2   Ack valid and or required*/
	const unsigned char SBIT2 = 0x04; /* 3rd bit = 4   Ack type (-ve/+ve)*/
	const unsigned char SBIT3 = 0x08; /* 4th bit = 8   Has Address is actually Has Length*/ /* TODO findout why this doesnt match the protocol docs */
	const unsigned char SBIT4 = 0x10; /* 5th bit = 16  Has Length */
	const unsigned char SBIT5 = 0x20; /* 6th bit = 32  FirmWare specific */
	const unsigned char SBIT6 = 0x40; /* 7th bit = 64  FirmWare specific */
	const unsigned char SBIT7 = 0x80; /* 8th bit = 128 FirmWare specific */

	/* statics */
	static char packetBuffer[MEGABYTE];
	static char payloadBuffer[MEGABYTE];

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
	unsigned int startBytesFound = 0;
	unsigned int packetsWithLength = 0;
	unsigned int payloadLength = 0;
	unsigned int correctPacketLength = 0;
	unsigned int incorrectPacketLength = 0;

	/* Loop and state variables */
	unsigned char currentCharacter = 0;
	unsigned char insidePacket = 0;
	unsigned char insidePayload = 0;
	unsigned int currentCharacterCount = 0;
	unsigned int packetCount = 0;
	unsigned int inFileLength = 0;
	unsigned char nextIsHeaderID = 0;
	unsigned char headerID = 0;
	unsigned char unescapeNext = 0;


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
		//	if((currentCharacter == START_BYTE) && insidePacket){
		//	  doubleStartByteOccurances++;
		//	}
			char escapePair0 = 0;
			char escapePair1 = 0;
			escapePair0 = fgetc(inputFile);
			escapePair1 = fgetc(inputFile);
			if ((escapePair0 == ESCAPE_BYTE) && (escapePair1 == ESCAPED_START_BYTE)){
				////////////////////////

			}else {
				fseek(inputFile,-2,SEEK_CUR);
				insidePacket = 1;
				packetPosition = 0;
				startBytesFound++;
				nextIsHeaderID = 1;
			}
		    /* we are expecting the next char to be the headerID(byte) */
		}else if ((currentCharacter != START_BYTE) && nextIsHeaderID){ /* if our packet header says there's a length calculate it */
			      if (currentCharacter && SBIT4){ /* if there is a payload length flag find the length */
			    	  headerID = currentCharacter;// TODO FIX returns 24 for some reason | SBIT4; /* figure out our ID so we know where our Length of Payload Bytes Are */
			    	  if (headerID == SBIT3){  /* TODO build switch case for all IDs */
			    		  /* TODO add checksum checking which should come right before the stop byte */
			    		  unsigned char bufferChar = 0;
			    		  unsigned int i = 0;
			    		  char junk = fgetc(inputFile);
			    		  junk = fgetc(inputFile);  /* TODO do this the correct way with fseek maybe */
			    		  payloadLength = getWord(inputFile);
			    	//	  printf("\nLength is -> %d",payloadLength);
			    		  while (insidePacket){
			    			  bufferChar = fgetc(inputFile);
			    			//  payloadBuffer[i] = bufferChar;
			    			  printf("\n char %x",bufferChar);
			    			  i++;
			    			  printf("\n count is %d",i);
			    			  junk = getchar();
			    		  }
                          if(bufferChar == STOP_BYTE ){
                        	  correctPacketLength++;
                        	//  junk = getchar();
                          } else if (bufferChar != STOP_BYTE){
                        	  incorrectPacketLength++;
                        	//  junk = getchar();
                          }
			    		  packetsWithLength++;
			    	  }
			    	//  printf("\n HeaderID is %d",headerID);
			    	  nextIsHeaderID = 0;
			      }
			//
			}
	//	if (insidePacket){
	//		packetPosition++;
	//	}
	}
    printf("\n Conents of Payload Buffer %s", payloadBuffer);
    printf("\n            Packets with Good Payload -> %d",correctPacketLength);
    printf("\n Packets With Bad Payload Or Checksum -> %d",incorrectPacketLength);
	printf("\n                        Bytes In File -> %d",currentCharacterCount);
    printf("\n                   Packet Start Bytes -> %d",startBytesFound);
    printf("\n               Packets with HasLength -> %d",packetsWithLength);
    printf("\n             Double Start Bytes Found -> %d",doubleStartByteOccurances);
    printf("\n");
	return 0;
}

unsigned int getWordSpecial(unsigned int filePosition,unsigned int file, char option, unsigned int advance){
    unsigned int savedPosition = filePosition;
    unsigned char low = 0;
    unsigned char high = 0;
    unsigned int word = 0;
    if (option == NORMAL){
    	 high = fgetc(file);
    	 low = fgetc(file);
    	 word = ((int)high << 8) + low;
    }
    if(option == NORMAL_RETURN){
    //	ungetc(file);
   // 	ungetc(file);
    }
	return word;
}

unsigned int getWord(unsigned int file){
	unsigned int word = 0;
	unsigned char low = 0;
	unsigned char high = 0;
	high = fgetc(file);
	low = fgetc(file);
	word = ((int)high << 8) + low;
	return word;
}
