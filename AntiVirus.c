/*********************************
* Class: MAGSHIMIM C2			 *
* Week: 23               		 *
* Name: shahar                   *
* Credits:                       *
**********************************/

#include <stdio.h>

#include <string.h>

#include <stdlib.h>

#include "dirent.h"

#include <wchar.h>

#include <stdbool.h>

#define FILE_PATH_SIZE 100 

#define FIRST_PART 1 

#define LAST_PART 2 

#define REGULAR_SCAN 0 

#define MAX_FILES 100 

bool scan(char* targetFilePath, char* signatureFilePath, int scanType); 

void sortStrings(char arr[][FILE_PATH_SIZE], int n); 

int main(int argc, char* argv[]) 
{
    //declare all the variables
    FILE* logFile = ""; 
    char filePaths[MAX_FILES][FILE_PATH_SIZE] = { 0 }; 
    char logPath[FILE_PATH_SIZE] = "\0"; 
    int result = 0; 
    int first = 0; 
    int last = 0; 
    int choice = 0; 
    int i = 0; 
    int size = 0; 
    int j = 0; 
    int num = 0; 

    //check if correct number of command-line arguments are provided
    if (argc != 3) 
    {
        printf("error opening file");
        return 1;
    }

    //construct log file path
    strcpy(logPath, argv[1]);
    strcat(logPath, "/");
    strcat(logPath, "AntiVirusLog.txt");

    //open log file for writing
    logFile = fopen(logPath, "w");
    if (logFile == NULL) 
    {
        printf("Could not open log file");
        return 1;
    }

    //write initial message to log file and also print the menu
    fprintf(logFile, "Anti-virus began! Welcome!\n\n");
    printf("Welcome to my Virus Scan!\n\n");
    fprintf(logFile, "Folder to scan:\n %s\n", argv[1]);
    printf("Folder to scan: %s\n", argv[1]);
    fprintf(logFile, "Virus signature:\n %s\n\n", argv[2]);
    printf("Virus signature: %s\n\n", argv[2]);

    //ask user for scan type
    fprintf(logFile, "Scanning option:\n");
    printf("Press 0 for a normal scan or any other key for a quick scan: ");
    scanf("%d", &choice);
    getchar();

    // Log scan type
    if (choice) 
    {
        fprintf(logFile, "Quick Scan\n\n");
    }
    else 
    {
        fprintf(logFile, "Normal Scan\n\n");
    }

    printf("Scanning began...\n");
    printf("This process may take several minutes...\n\n");
    printf("Scanning:\n");
    fprintf(logFile, "Results:\n");

    //open directory for scanning
    DIR* d = 0;
    struct dirent* dir = 0;
    d = opendir(argv[1]);
    if (d == NULL) 
    {
        printf("Error opening directory");
        return 1;
    }

    //read file paths from directory and add it to filePaths in place i
    while ((dir = readdir(d)) != NULL) 
    {
        if (strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..")) 
        {
            if (i < MAX_FILES) 
            {
                snprintf(filePaths[i], FILE_PATH_SIZE, "%s/%s%s", argv[1], dir->d_name, "\0");
                i++;
            }
            else 
            {
                break;
            }
        }
    }

    num = i; //number of files to scan
    sortStrings(filePaths, i); //sort file paths alphabetically (with bubble sort)

    //iterate through files and scan for viruses
    for (i = 0; i < num; i++) 
    {

        fprintf(logFile, "%s", filePaths[i]);
        printf("%s", filePaths[i]);

        result = scan(filePaths[i], argv[2], REGULAR_SCAN); //perform regular scan
        
        if (result) 
        {
            fprintf(logFile, "  Infected!");
            printf(" - Infected!");
            if (choice) 
            {
                first = scan(filePaths[i], argv[2], FIRST_PART); //perform first part scan
                if (first) 
                {
                    fprintf(logFile, "  (first 20%%)");
                    printf(" (first 20%%)");
                }
                else 
                {
                    last = scan(filePaths[i], argv[2], LAST_PART); //perform last part scan
                    if (last) 
                    {
                        fprintf(logFile, "  (last 20%%)");
                        printf(" (last 20%%)");
                    }
                }
            }
        }
        else 
        {
            fprintf(logFile, "  Clean");
            printf(" - Clean");
        }
        fprintf(logFile, "\n");
        printf("\n");
    }

    printf("Scan Completed.\n");
    printf("See log path for results: %s\n", logPath);

    //close directory and log file
    closedir(d);
    fclose(logFile);
    getchar();
    return 0;
}

/*
function to sort an array of strings alphabetically (with bubble sort)
input: char arr[][FILE_PATH_SIZE], int n
output: none
*/
void sortStrings(char arr[][FILE_PATH_SIZE], int n) {
    char temp[FILE_PATH_SIZE]; //temporary string for swapping

    //sorting strings using bubble sort
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - 1 - i; j++) {
            if (strcmp(arr[j], arr[j + 1]) > 0) {
                strcpy(temp, arr[j]);
                strcpy(arr[j], arr[j + 1]);
                strcpy(arr[j + 1], temp);
            }
        }
    }
}

/*
function to scan a file for viruses
input: char* targetFilePath, char* signatureFilePath, int scanType
output: bool isInfected
*/
bool scan(char* targetFilePath, char* signatureFilePath, int scanType) 
{
    long index = 0; //index for scanning file
    long targetFileSize2 = 0; //size of target file after adjustment
    int offsetAdjustment = 0; //offset adjustment for scanning
    FILE* targetFile = fopen(targetFilePath, "rb"); //open target file for reading (binary)
    
    if (targetFile == NULL) 
    {
        fclose(targetFile);
        return false;
    }

    //get size of target file
    fseek(targetFile, 0, SEEK_END);
    long targetFileSize = ftell(targetFile);
	fseek(targetFile, 0, SEEK_SET);

	FILE* signatureFile = fopen(signatureFilePath, "rb");  //open signature file for reading (binary)
	
    if (signatureFile == NULL)
	{
		fclose(targetFile);
		fclose(signatureFile);
		return false;
	}
    //get size of signature file
    fseek(signatureFile, 0, SEEK_END);
	long signatureFileSize = ftell(signatureFile);
	fseek(signatureFile, 0, SEEK_SET);
	
    //if signature file size is bigger than target file size close all the files and return false
	if (signatureFileSize > targetFileSize)
	{  
		fclose(targetFile);  
		fclose(signatureFile);  
		return false;  
	}

	bool isInfected = false;  
	char* targetBuffer = (char*)malloc(targetFileSize); //create targetBuffer using malloc (size: targetFileSize)

	if (targetBuffer == NULL)
	{
		free(targetBuffer);
		fclose(targetFile);
		fclose(signatureFile);
		return false;
	}

	char* signatureBuffer = (char*)malloc(signatureFileSize); //create signatureBuffer using malloc (size: signatureFileSize)

	if (signatureBuffer == NULL)
	{
		free(targetBuffer);
		free(signatureBuffer);
		fclose(targetFile);
		fclose(signatureFile);
		return false;

	}

	fread(signatureBuffer, sizeof(char), signatureFileSize, signatureFile); 
    
    //if scanType == FIRST_PART, scan only the first 20%
	if (scanType == FIRST_PART)
	{
		targetFileSize = targetFileSize * 0.2;
	}
	else if (scanType == LAST_PART) //else if scanType == LAST_PART, scan only the last 20%
	{
		targetFileSize2 = targetFileSize * 0.8;
	}
    
    //for loop the check if targetBuffer contains signatureBuffer
	for (index = 0; index <= targetFileSize - signatureFileSize; index++)
	{  
        //start reading from index + targetFileSize2 and read only the size of signature
		fseek(targetFile, index + targetFileSize2, SEEK_SET);
		fread(targetBuffer, sizeof(char), signatureFileSize, targetFile);

		if (memcmp(targetBuffer, signatureBuffer, signatureFileSize) == 0)
		{  
            //if targetBuffer contains signatureBuffer, isInfected = TRUE
			isInfected = true;  
			break;  
		}
	}
	
    //free and close all the buffers and files
	free(targetBuffer);  
	free(signatureBuffer);  
	fclose(targetFile);  
	fclose(signatureFile);  

    //return isInfected (TRUE or FALSE)
	return isInfected;  
}

