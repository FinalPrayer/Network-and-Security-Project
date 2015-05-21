/*
 Network and Security Project - General Algorithm
 
 The algorithm list below will be useful for all sides.
 */
#include "general.h"

int file_detection(const char *filename) {
    FILE *filedata = NULL;
    filedata = fopen(filename, "r");
    if (filedata != NULL)
    {
        fclose(filedata);
        return 1;//Assume if the data exists, then return 1
    }
    fclose(filedata);
    return 0;// Assume if the data does not exists, then return 0.
}

/*
 Bank side Authentication code
 
 The bank will return the code to all the clients after their authentication,
 which clients can know why the bank will reject their login.
 */
int auth_code(int authentication_result) {
    switch(authentication_result) {
        case 0:
            printf("Success!\n");
            return 0;
        case 400:
            printf("INVALID ARGUMENT!\nPlease check again for the argument sent to the server.\n");
            return 1;
        case 404:
            printf("404 - Not Found\nYour account does not exist. Please check again.\n");
            return 1;
        case 403:
            printf("403 - Forbiddon\nYour password is incorrect, please check again.\n");
            return 1;
        case 1300:
            printf("eCent Ownership invalid\nYou are not owning this eCent. Ask the original for further notice.\n");
            return 1;
        case 1301:
            printf("eCent not found\nPlease check the eCent is correct or not.\n");
            return 1;
        case 1400:
            printf("Account data not found\nYour Account has not yet been register, are you the hacker?\n");
            return 1;
        case 1402:
            printf("Device is Already registered\nYou are not required to register again.\n");
            return 1;
        case 1403:
            printf("Device Authentication Failed\nThis account has been already registered to another device.\n"
                   "If you think this is your another device, forget this message.\n If not, go to the bank to clear your history.");
            return 1;
        case 1404:
            printf("Device not yet Registered\nYou cannot use eCent function without register.\n");
            return 1;
        case 1405:
            printf("Warning: device registration with different IP address\nPlease contact the director if you moved your server.\n");
            return 1;
        case 2404:
            printf("Analysis List not Found.\nNone of device available for decode your stuff found.\n");
            return 1;
        default:
            printf("Incorrect Value.\n");
    }
    return 1;
}
