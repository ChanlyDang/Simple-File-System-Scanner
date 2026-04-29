#include <stdio.h>
#include <windows.h>
#include <string.h>

//function calls for file time of creation and time of modification
void CreationTime(FILETIME directory, FILE *output);
void ModifiedTime(FILETIME directory_M, FILE *output);

int main() {
    // directory I want to scan"E:\\No Malware Zone\\Malware"
    WIN32_FIND_DATA scanned_directory; // defined struct here for obtaining the computing resources in the windows file system
    HANDLE hFind; // defined handle here for tracking resources
    char fileTypes[][6] = {".exe", ".zip", ".xlsm", ".vbs", ".ps1", ".bat", ".cmd", ".iso", ".dll"}; // file types that hold malware: .exe, .zip, .xlsm, .vbs, .ps1, .bat, .cmd, .iso, .dll
    // Use * to get all the files names of the directory, use the file name for just one file
    // the parameters for FindFirstFile(for ANSI) are (given directory, given structure for finding the directory using Windows API, dont forget pointer address symbol)
    hFind = FindFirstFile("C:\\path\\to\\files\\*", &scanned_directory); 
    FILE *file = fopen("C:\\path\\to\\scan_results.txt", "w"); 

    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();

        if (error == ERROR_FILE_NOT_FOUND) {
            printf("No files found in directory.\n");
        } 
        else if (error == ERROR_PATH_NOT_FOUND) {
            printf("The specified path is invalid.\n");
        }
        else {
            printf("FindFirstFile failed with error %lu\n", error);
        }
    } 
    else {
        printf("Files Found\n");
    }


    // used a do while loop for recursive iteration in the given directory
    do {
        // this is how to shift numbers to a place in memory, in this instance, needed for a 64-bit number since 32 bits is the max 
        unsigned long long combined_filesize = (unsigned long long) scanned_directory.nFileSizeHigh << 32 | (unsigned long long) scanned_directory.nFileSizeLow; 
        // this if statement gets rid of referential directories, i.e the current directory and parent directory information
        if (strcmp(scanned_directory.cFileName, ".") == 0 || strcmp(scanned_directory.cFileName, "..") == 0) {
            // continue is used to skip the rest of the current loop iteration and move on to the next one, meaning don't run any other code
            continue;
        }
        // this for loop runs through the fileTypes string array, shown as a matrix, and uses the strstr function to ask if the substring (second parameter), exist inside the main string (first parameter)
        // and then it runs the functions that I need. else, skip the rest of the code and move on to the next iteration (just like above)
        for (int i = 0; i < 9; i++) {
            if (strstr(scanned_directory.cFileName, fileTypes[i])) {
                fprintf(file, "File name: %s\n", scanned_directory.cFileName);
                CreationTime(scanned_directory.ftCreationTime, file);
                ModifiedTime(scanned_directory.ftLastWriteTime, file);
                // lld is the format specifier for an signed long long, llu is for unsigned long long
                fprintf(file, "File Size: %llu\n\n", combined_filesize);
            }
            else {
                continue;
            }
        }

    
    } while (FindNextFile(hFind, &scanned_directory)); // finding the next file when the function still runs to keep handle open (find first file) at scanned_directory address
    if (hFind != INVALID_HANDLE_VALUE){
        printf("Scanning completed. See scan results at scan_results.txt");
    }
    // you close this handle like you have to free memory. It is a reference to the directory and files as a resource, so you close it to write clean code
    FindClose(hFind);
    fclose(file);
    return 0;
}

void CreationTime(FILETIME directory, FILE *output) {
    FILETIME ftCreate = directory;
    SYSTEMTIME sys_time, sys_time_local;
    FileTimeToSystemTime(&ftCreate, &sys_time);
    SystemTimeToTzSpecificLocalTime(NULL, &sys_time, &sys_time_local);
    fprintf(output, "File Created: %02d-%02d-%04d %02d:%02d:%02d\n", 
        sys_time_local.wMonth, sys_time_local.wDay, sys_time_local.wYear, sys_time_local.wHour, sys_time_local.wMinute, sys_time_local.wSecond);
}

void ModifiedTime(FILETIME directory_M, FILE *output) {
    // call this struct FILETIME with the creation time field variable inside the Windows struct from the windows header. Windows APIs have their own field variables
    FILETIME ftModified = directory_M;
    // calling our own variables to hold time data in a readable format. SYSTEMTIME is a windows struct that store human-readable time
    SYSTEMTIME sys_time_M, sys_time_local_M;
    //this converts the computer's time (big number calculated by computer) to the human time (dates and times), my error was not converting it early
    FileTimeToSystemTime(&ftModified, &sys_time_M);
    //converts the human time to YOUR local time of the system (the region), so UTC is the default sys_time, but now it converts it to EST (my time)
    SystemTimeToTzSpecificLocalTime(NULL, &sys_time_M, &sys_time_local_M);
    // print out the date and time with the field variables from SYSTEMTIME struct
    fprintf(output, "File Modified: %02d-%02d-%04d %02d:%02d:%02d\n", 
        sys_time_local_M.wMonth, sys_time_local_M.wDay, sys_time_local_M.wYear, sys_time_local_M.wHour, sys_time_local_M.wMinute, sys_time_local_M.wSecond);
}

