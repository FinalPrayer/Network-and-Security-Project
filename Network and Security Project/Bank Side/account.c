/*
 Network and Security project - Bank side
 Account Struct file
 
 This file is run during the first time the bank application run,
 it will struct some account infomation */

#include "bank.h"

/*
 File detection for the bank account file.
 If the data does not exists, then return 0, or else, return 1.
 */
int bank_acct_init_exists(){
    int bank_acct_bool = file_detection("accounts.txt");
    if (bank_acct_bool == 1) {
        return 1; //Assume if the file detection o
    }
    return 0;
}

/*
 So this is step one, make sure if the account information exists
 
 Assuming the format is:
 column 1: Account number - up to 5 digits (in experimental).
 column 2: the password, aims for verify ownership.
 column 3: the balance.
 */
int bank_acct_init() {
    FILE *waste = fopen("DO NOT MODIFY ANYTHING HERE", "w");
    fclose(waste);
    FILE *accountdata;
    accountdata = fopen("accounts.txt", "w+");
    int col_acctnum = COLLECTER_ACCT_NUM;   //collecter account number
    char *col_pass = COLLECTER_ACCT_PASS;   //collecter account password
    float col_balance = COLLECTER_BALANCE;  //collecter balance
    fprintf(accountdata, "%i\t%s\t%f\n",col_acctnum, col_pass, col_balance);
    int ana_acctnum = ANALYSIS_ACCT_NUM;    //analysis account number
    char *ana_pass = ANALYSIS_ACCT_PASS;    //analysis account password
    float ana_balance = ANALYSIS_BALANCE;   //analysis balance
    fprintf(accountdata, "%i\t%s\t%f\n", ana_acctnum, ana_pass, ana_balance);
    fclose(accountdata);
    return 0;//means this process has been complete.
}

/*
 Here is the startup detection. Detect if the account page exists.
 If yes, do nothing. If no, generate the account page with initialisation data.
 */
int startup_detection() {
    //step one, check if file exists.
    int file_bool = bank_acct_init_exists();
    if (file_bool == 0)
        bank_acct_init();
    return 0;
}

/*Account Authorization
 
 This part is aims to authorize the account with their password/
 */
int acct_authentication(int acct, char* pass) {
    int acct_num=acct;
    char* acct_pass=pass;
    //open the account data file
    FILE *accountdata = fopen("accounts.txt", "r+");
    //setup some var that may change itself.
    size_t linecap = 0;
    char *line = NULL;
    ssize_t linelen;
    //load by line
    while ((linelen = getline(&line, &linecap, accountdata)) > 0) {
        //use strtok to split the line to variable to use.
        int accountNumber = atoi(strtok(line, "\t"));
        char *accountPassword = strtok(NULL, "\t");
        if (acct_num == accountNumber) {
            if (strcmp(acct_pass,accountPassword) == 0) {
                //Success
                fclose(accountdata);
                return 0;
            } else {
                //403 Forbiddon, password incorrect.
                fclose(accountdata);
                return 403;
            }
        }
    }
    //404 not found - Account not found.
    fclose(accountdata);
    return 404;
}

/*
 Device Authentication
 
 This algorithm is aims to check if any other device are registered.
 nah, I would like to said if other device has been registered I will ask them to
 GO TO THE BANK AND SOLVE YOURSELF!!!
 */
int device_authentication(int account_number, int deviceID) {
    FILE *device = fopen("device.txt", "r");
    size_t linecap = 0;
    char *line = NULL;
    ssize_t linelen;
    //load by line
    while ((linelen = getline(&line, &linecap, device)) > 0) {
        int acct_num = atoi(strtok(line, "\t"));
        int dev_ID = atoi(strtok(NULL, "\n"));
        if (account_number == acct_num && deviceID == dev_ID)
            return 1402;
        else
            return 1403;
    }
    return 0;
}

/*
 Device Registration
 to make sure the eCent can be generate for the device, the device
 should be register to the account, and this algorithm can done this.
 
 For the safety reason, one account only available to register one device.
 And the file to save the device ID will be called device.txt
 
 The device.txt has the initial structure:
 Column 1: the account number and
 Column 2: the device ID.
 */
int device_registration(int account_number, char* password, int deviceID) {
    //first step, verify if the account exist and the password correct.
    int auth_result = acct_authentication(account_number, password);

    if (auth_result == 0) {
        if (file_detection("device.txt") == 1) {
            int dev_auth = device_authentication(account_number, deviceID);
            if (dev_auth == 0) {
                FILE *device = fopen("device.txt", "a+");
                fprintf(device, "%i\t%i\n", account_number, deviceID);
                fclose(device);
                return 0;
            }
            else
                return dev_auth;    //return the error code from device auth.
        }
        else {
            FILE *device = fopen("device.txt", "w+");
            fprintf(device, "%i\t%i\n", account_number, deviceID);
            fclose(device);
            return 0;
        }
    }
    else
        return auth_result; //return the error code from account auth.
}

//Find devices.
int device_find(int deviceID) {
    FILE *device = fopen("device.txt", "r");
    size_t linecap = 0;
    char *line = NULL;
    ssize_t linelen;
    //load by line
    while ((linelen = getline(&line, &linecap, device)) > 0) {
        int acct_num = atoi(strtok(line, "\t"));
        int dev_ID = atoi(strtok(NULL, "\n"));
        if (deviceID == dev_ID)
            return acct_num;
    }
    return -1;
}
