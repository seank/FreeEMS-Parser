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
#define CONFIGF_FILE            "config.cfg"
#define NORMAL                  "0x00"
#define SEEK                    "0x01"
#define NORMAL_RETURN           "0x02"
#define SEEK_RETURN             "0x03"
#define HEADER                  "IAT,CHT,TPS,EGO,MAP,AAP,BRV,MAT,EGO2,IAP,MAF,DMAP,DTPS,RPM,DRPM,DDRPM,LoadMain,VEMain,Lambda,AirFlow,DensityFuel,BasePW,IDT,ETE,TFCTotal,FinalPW,RefPW,sp1,sp2,sp3,sp4,sp5,adc0,adc1,adc2,adc3,adc4,adc5,adc6,adc7,adc8,adc9,adc10,adc11,adc12,adc13,adc14,adc15"

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

/* Checksum Function
 * so if you have 0x12 0xBB 0x44 0x35 then the sum is of 0x12 0xCC 0x35
 */

/* TODO move to header */
unsigned char calcPayloadCheckSum(unsigned int size);
unsigned char writeOutBuffer(FILE *outputFile);
unsigned long int getBufferWord(unsigned int hiByte);
unsigned int writeString(double value,FILE *outputFile);
unsigned int writeHeader(FILE *outputFile);

/*********************  STATICS **********************************/
static char payloadBuffer[MEGABYTE]={0};
static int payloadBufferIndex = 0; /* next free position in buf */

static char wroteHeader = 0;

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
//	static char packetBuffer[MEGABYTE];


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
	unsigned int packetsWithoutLength = 0;
	unsigned int payloadLength = 0;
	unsigned int correctPacketLength = 0;
	unsigned int incorrectPacketLength = 0;
	unsigned int corruptPackets = 0;
	unsigned int faseStarts = 0;
	unsigned int unknownHeaderIDCount = 0;

	/* Loop and state variables */
	unsigned char currentCharacter = 0;
	unsigned char insidePacket = 0;
	unsigned char insidePayload = 0;
	unsigned int currentCharacterCount = 0;
	unsigned int packetCount = 0;
	unsigned long int inFileLength = 0;
	unsigned char nextIsHeaderID = 0;
	unsigned char headerID = 0;
	unsigned char unescapeNext = 0;
	unsigned char checksum = 0;
    unsigned char checkSumByte = 0;

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
	unsigned int bufferIndex = 0;
	while (currentCharacterCount < inFileLength ){
		if (!wroteHeader){
			writeHeader(outputFile);
		}
    	currentCharacter = fgetc(inputFile);
		currentCharacterCount++;
		if (currentCharacter == START_BYTE){
			if(insidePacket){
			doubleStartByteOccurances++;
			}else{
			insidePacket = 1;
			packetPosition = 0;
			startBytesFound++;
			nextIsHeaderID = 1;

			printf("\n new start found");
			}
		    /* we are expecting the next char to be the headerID(byte) */
		}else if ((currentCharacter != START_BYTE) && nextIsHeaderID){ /* if our packet header says there's a length calculate it */
			     bufferIndex = 0;
			     nextIsHeaderID = 0;
			//     checkSumByte = 0; /* clear checksum */
			//     checkSumByte += currentCharacter;
			     payloadBuffer[bufferIndex++] = currentCharacter;
			//     bufferIndex++;
			     if (currentCharacter && SBIT4){ /* if there is a payload length flag find the length */
			    	 headerID = currentCharacter;// TODO FIX returns 24 for some reason | SBIT4; /* figure out our ID so we know where our Length of Payload Bytes Are */
			    	  if (headerID == SBIT3){  /* TODO build switch case for all IDs */
			    		  /* TODO add checksum checking which should come right before the stop byte */
			    //		  unsigned char bufferChar = 0;

			        //      fseek(inputFile,2,SEEK_CUR); / * cannot skip or checksum will be off */
			    		  currentCharacter = fgetc(inputFile);
			    		  currentCharacterCount++;
			    		  payloadBuffer[bufferIndex++] = currentCharacter;
			   // 		  bufferIndex++;
			  //  		  checkSumByte += currentCharacter;
			    		  currentCharacter = fgetc(inputFile);
			    		  currentCharacterCount++;
			    		  checkSumByte += currentCharacter;
			    		  payloadBuffer[bufferIndex++] = currentCharacter;
			       	      unsigned char high = fgetc(inputFile);
			    	      currentCharacterCount++;
			       	      payloadBuffer[bufferIndex++] = high;
			       	      unsigned char low = fgetc(inputFile);
			    	      currentCharacterCount++;
			    	      payloadBuffer[bufferIndex++] = low;
			      	      payloadLength = ((int) high << 8) + low;
			       		  while (insidePacket){
			    			  printf("\n current Character -> %x",currentCharacter);
			    			  currentCharacter = fgetc(inputFile);
			    			  currentCharacterCount++;
			    			  unsigned char escapedPair = 0;
			    			  unsigned char falseEscape = 1;
			    			  if(currentCharacter == ESCAPE_BYTE){
			    			    /*All packets start with STX, and end with ETX. Should any of STX, ETX or ESC occur within the
			    				  packet contents (including the header and checksum), it must be “escaped”, with a preceding
			    				  ESC byte and the byte itself XOR'ed with the value 0xFF. This will yield the following easy to
			    				  recognise pairs in the stream : */
                                 falseEscape = 1; /* guilty until proven innocient */
			    				 escapedPair = fgetc(inputFile);
			    				 /* do not use an escape_byte to calc sum */
			    				 currentCharacterCount++;
			    				 if(escapedPair == ESCAPED_ESCAPE_BYTE){
                                	 escapedEscapeBytesFound++;
                                	 payloadBuffer[bufferIndex++] = ESCAPE_BYTE;
                                   	 falseEscape = 0;
                                 }else if(escapedPair == ESCAPED_START_BYTE){
                                	 escapedStartBytesFound++;
                                	 payloadBuffer[bufferIndex++] = START_BYTE;
                                   	 falseEscape = 0;
                                 }else if(escapedPair == ESCAPED_STOP_BYTE){
                                	 escapedStopBytesFound++;
                                  	 payloadBuffer[bufferIndex++] = STOP_BYTE;
                                   	 falseEscape = 0;
                                 }else if ((currentCharacter == ESCAPE_BYTE) && falseEscape){
			    				  fseek(inputFile, -1,SEEK_CUR);
			    				  currentCharacterCount--;
			    				  corruptPackets++;
			    				  insidePacket = 0;
			    				  // TODO add invalid escape count
			    			  }
			    	      }else if(currentCharacter == START_BYTE){
		    				  corruptPackets++;
		    				  insidePacket = 0;
			    		  }else if(currentCharacter == STOP_BYTE){
                              insidePacket = 0;
			    			  unsigned char checkSum = payloadBuffer[--bufferIndex]; /* the previous byte in the buffer should be the checksum */
			    	          checkSumByte = calcPayloadCheckSum(bufferIndex);
			    			  printf("\n buffer size %d",bufferIndex);
			    			  if ( checkSum == checkSumByte){
			    				  printf("\n good sum found %x",checkSum);
			    				  goodChecksums++;
			    			    //  char pause = getchar();
			    				  writeOutBuffer(outputFile);
			    			 }else {
			    				 corruptPackets++;
			    			     printf("\n   bad sum found buffer %x ",checkSum);
			    				 printf("\n bad sum calced %x ",checkSumByte);
			    				 printf("\n sum is now -> %d",checkSumByte);
			    		    	 char jjunk = getchar();

			    			 }
			    		  }else if(insidePacket){
			    			    payloadBuffer[bufferIndex++] = currentCharacter;
			    	   }
			    		  packetsWithLength++;
			    	  }
			      } else {
			    	  corruptPackets++;
			    	  unknownHeaderIDCount++;
			    	  printf("\n Unprovisioned HeaderID");
			    	  insidePacket = 0;
			   	      }
			     }

			}
	}
 //   printf("\n            Conents of Payload Buffer %s", payloadBuffer);
    printf("\n               Packets with unknown headerID -> %d",unknownHeaderIDCount);
    printf("\nCorrupt packets that MS would have just used!-> %d",corruptPackets);
    printf("\n                  Packets with Good checksum -> %d",goodChecksums);
    printf("\n                  Escaped Escape Bytes Found -> %d",escapedEscapeBytesFound);
    printf("\n                   Escaped Start Bytes Found -> %d",escapedStartBytesFound);
    printf("\n                    Escaped Stop Bytes Found -> %d",escapedStopBytesFound);
    printf("\n              Packets Without Payload Length -> %d",packetsWithoutLength);
    printf("\n                      Packets with HasLength -> %d",packetsWithLength);
    printf("\n                   Packets with Good Payload -> %d",correctPacketLength);
    printf("\n             Packets With Bad Payload Length -> %d",incorrectPacketLength);
	printf("\n                               Bytes In File -> %d",currentCharacterCount);
    printf("\n                         Packet Starts Found -> %d",startBytesFound);
    printf("\n                    Double Start Bytes Found -> %d",doubleStartByteOccurances);
    printf("\n");
	printf("\n\n\nThank you for choosing FreeEMS! c. Sean Keys see contribs at diyefi.org for a full list of contributors");
    return 0;
}


unsigned char calcPayloadCheckSum(unsigned int size){
	printf("\n size %d",size);
	unsigned int i;
	char checksum = 0;
	for(i=0;i < size;i++){ // CANNOT USE PAYLOAD SIZE FROM HEADER
		unsigned char value = payloadBuffer[i];
		checksum += value;
		printf("\n %x ",value);
	}
//	char pause = getchar();
	return checksum;
}

unsigned char writeOutBuffer(FILE *outputFile){
/*     # Data log packet payload order
       _structure = [ 'IAT', 'CHT', 'TPS', 'EGO', 'MAP', 'AAP', 'BRV', 'MAT',
       'EGO2', 'IAP', 'MAF', 'DMAP', 'DTPS', 'RPM', 'DRPM', 'DDRPM',
       'LoadMain', 'VEMain', 'Lambda', 'AirFlow', 'DensityFuel', 'BasePW',
       'IDT', 'ETE', 'TFCTotal', 'FinalPW', 'RefPW', 'sp1', 'sp2', 'sp3',
       'sp4', 'sp5', 'adc0', 'adc1', 'adc2', 'adc3', 'adc4', 'adc5', 'adc6',
       'adc7', 'adc8', 'adc9', 'adc10', 'adc11', 'adc12', 'adc13', 'adc14',
       'adc15', ] */
	    // unsigned int retrievedValue = 0;
    	double retrievedValue = 0.0f;
	    /* get IAT */
		retrievedValue = (getBufferWord(5) / 100) - 273.15;
		writeString(retrievedValue,outputFile);
		/* get CHT */
		retrievedValue = (getBufferWord(7) / 100) - 273.15;
		writeString(retrievedValue,outputFile);
		/* get TPS */
		retrievedValue = getBufferWord(9) / 640;
		writeString(retrievedValue,outputFile);
		/* get EGO */
		retrievedValue = getBufferWord(11);
		writeString(retrievedValue,outputFile);
		/* get MAP */
		retrievedValue = getBufferWord(13) / 100;
		writeString(retrievedValue,outputFile);
		/* get AAP */
		retrievedValue = getBufferWord(15) / 100;
		writeString(retrievedValue,outputFile);
		/* get BRV */
		retrievedValue = getBufferWord(17);
		writeString(retrievedValue,outputFile);
		/* get MAT */
		retrievedValue = (getBufferWord(19) / 100) - 273.15;
		writeString(retrievedValue,outputFile);
		/* get EGO2 */
		retrievedValue = getBufferWord(21);
		writeString(retrievedValue,outputFile);
		/* get IAP */
		retrievedValue = getBufferWord(23) / 100;
		writeString(retrievedValue,outputFile);
		/* get MAF */
		retrievedValue = getBufferWord(25);
		writeString(retrievedValue,outputFile);
		/* get DMAP */
		retrievedValue = getBufferWord(27);
		writeString(retrievedValue,outputFile);
		/* get DTPS */
		retrievedValue = getBufferWord(29);
		writeString(retrievedValue,outputFile);
		/* get RPM */
    	retrievedValue = getBufferWord(31) / 2;
	    writeString(retrievedValue,outputFile);
	    /* get DRPM */
	    retrievedValue = getBufferWord(33);
	    writeString(retrievedValue,outputFile);
	    /* get DDRPM */
	    retrievedValue = getBufferWord(35);
	    writeString(retrievedValue,outputFile);
	    /* get LoadMain */
	    retrievedValue = getBufferWord(37);
	    writeString(retrievedValue,outputFile);
	    /* get VEMain */
	    retrievedValue = getBufferWord(39);
	    writeString(retrievedValue,outputFile);
	    /* get Lambda */
	    retrievedValue = getBufferWord(41);
	    writeString(retrievedValue,outputFile);
	    /* get AirFlow */
	    retrievedValue = getBufferWord(43);
	    writeString(retrievedValue,outputFile);
	    /* get densityFuel */
	    retrievedValue = getBufferWord(45);
	    writeString(retrievedValue,outputFile);
	    /* get BasePW */
	    retrievedValue = getBufferWord(47);
	    writeString(retrievedValue,outputFile);
	    /* get IDT */
	    retrievedValue = getBufferWord(49);
	    writeString(retrievedValue,outputFile);
	    /* get ETE */
	    retrievedValue = getBufferWord(51);
	    writeString(retrievedValue,outputFile);
	    /* get TFCTotal */
	    retrievedValue = getBufferWord(53);
	    writeString(retrievedValue,outputFile);
	    /* get FinalPW */
	    retrievedValue = getBufferWord(55);
	    writeString(retrievedValue,outputFile);
	    /* get RefPW */
	    retrievedValue = getBufferWord(57);
	    writeString(retrievedValue,outputFile);
	    /* get sp1 */
	    retrievedValue = getBufferWord(59);
	    writeString(retrievedValue,outputFile);
	    /* get sp2 */
    	retrievedValue = getBufferWord(61);
	    writeString(retrievedValue,outputFile);
	    /* get sp3 */
	    retrievedValue = getBufferWord(63);
	    writeString(retrievedValue,outputFile);
	    /* get sp4 */
	    retrievedValue = getBufferWord(65);
	    writeString(retrievedValue,outputFile);
	    /* get sp5 */
	    retrievedValue = getBufferWord(67);
	    writeString(retrievedValue,outputFile);
	    /* get adc0 */
	    retrievedValue = getBufferWord(69);
	    writeString(retrievedValue,outputFile);
	    /* get adc1 */
	    retrievedValue = getBufferWord(71);
	    writeString(retrievedValue,outputFile);
	    /* get adc2 */
	    retrievedValue = getBufferWord(73);
	    writeString(retrievedValue,outputFile);
	    /* get adc3 */
	    retrievedValue = getBufferWord(75);
	    writeString(retrievedValue,outputFile);
	    /* get adc4 */
	    retrievedValue = getBufferWord(77);
	    writeString(retrievedValue,outputFile);
	    /* get adc5 */
	    retrievedValue = getBufferWord(79);
	    writeString(retrievedValue,outputFile);
	    /* get adc6 */
	    retrievedValue = getBufferWord(81);
	    writeString(retrievedValue,outputFile);
	    /* get adc7 */
	    retrievedValue = getBufferWord(83);
	    writeString(retrievedValue,outputFile);
	    /* get adc8 */
	    retrievedValue = getBufferWord(85);
	    writeString(retrievedValue,outputFile);
	    /* get adc9 */
	    retrievedValue = getBufferWord(87);
	    writeString(retrievedValue,outputFile);
	    /* get adc10 */
	    retrievedValue = getBufferWord(89);
	    writeString(retrievedValue,outputFile);
	    /* get adc12 */
	    retrievedValue = getBufferWord(91);
	    writeString(retrievedValue,outputFile);
	    /* get adc13 */
	    retrievedValue = getBufferWord(93);
	    writeString(retrievedValue,outputFile);
	    /* get adc14 */
	    retrievedValue = getBufferWord(95);
	    writeString(retrievedValue,outputFile);
	    /* get adc 15 */
	    retrievedValue = getBufferWord(97);
	    writeString(retrievedValue,outputFile);

    fputc('0',outputFile); /* TODO make program smart enought to exclude the , after the last value */
    fputc('\n',outputFile); /* terminate end of row with a newline */

	return 0;
}

unsigned int writeString(double value,FILE *outputFile){
	char temp [20] = {0};
	sprintf(temp,"%f",value); /* get and format RPM */
	 /* TODO investigate using fputs */
    fputs(temp,outputFile);
    fputc(',',outputFile);
//	for(i=0; (c = temp[i]) != END_OF_STRING;i++){ /* sprintf add EOF */
//			fputc(c, outputFile);
//	   }
    return 0;
}

unsigned long int getBufferWord(unsigned int hiByte){
	unsigned long int word = 0.0f;
	unsigned char low = 0;
	unsigned char hi = 0;
	hi = payloadBuffer[hiByte];
	low = payloadBuffer[++hiByte];
	word = ((int)hi << 8) + low; /* move our first eight bits to high then add low */
	return word;
}

unsigned int writeHeader(FILE *outputFile){
    fputs(HEADER,outputFile);
    fputc('\n',outputFile);
    wroteHeader = 1;
    return 0;
}
