/*
 Network and Security Project - Bank side
 This is the bank side of the project.
 
 This file contains the transaction details,
 including the transaciton process algorithm, and the library of the code.
 
*/

#include "bank.h"

int fund_reduce(int eCentVolume, int account_num) {
    float moneyToCost = eCentVolume;
    FILE *accountData = fopen("accounts.txt", "r");
    FILE *accountDataNew = fopen("account_temp.txt", "w");
    size_t linecap = 0;
    char *line = NULL;
    ssize_t linelen;
    int match = 0;
    while ((linelen = getline(&line, &linecap, accountData)) > 0) {
        int accountNumber = atoi(strtok(line, "\t"));
        char *accountPassword = strtok(NULL, "\t");
        float balance = atof(strtok(NULL, "\n"));
        if (accountNumber == account_num) {
            if (moneyToCost <= balance) {
                match++;
                balance = balance - moneyToCost;
                fprintf(accountDataNew, "%i\t%s\t%f\n", accountNumber, accountPassword, balance);
            } else {
                fprintf(accountDataNew, "%i\t%s\t%f\n", accountNumber, accountPassword, balance);
            }
        } else {
            fprintf(accountDataNew, "%i\t%s\t%f\n", accountNumber, accountPassword, balance);
        }
    }
    fclose(accountData);
    fclose(accountDataNew);
    rename("account_temp.txt", "accounts.txt");
    if (match > 0) {
        return 0;
    } else {
        return 1400;
    }
}

int cash_to_eCent(int volumes, int deviceID) {
    /*
     This is the ecent convert program
     there procedure will be:
     1. check if the request volume of eCent can be convert by the account balance. If not return message
     2. reduce the balance, and use the ecent_generate to generate the ecent data.
     3. use the network to transfer the user ecent list. (that user list will remove after transmission.)
     
     This job will finish only after the client has been registered to the bank with their device ID.
     Or else it will return not registered message.
     */
    //step one, check if the device.txt exists, if not or if yes but not found the device linked, return error.
    if (file_detection("device.txt") == 1) {
        int dev_id=deviceID;
        int account_num = device_find(dev_id);
        if (account_num > 0) {
            //Step 2: reduce the funds. successfully will return 0, if not, parse them the error code.
            int reduce_result = fund_reduce(volumes, account_num);
            if (reduce_result == 0) {
                ecent_generate(volumes, dev_id);
                return 0;
            } else {
                return reduce_result;
            }
        }
    }
    return 1404;
}

int eCent_to_cash(char* eCent_address, int deviceID) {
    int account_num = device_find(deviceID);
    if (account_num > 0) {
        int used = 0;
        FILE *eCentorig = fopen("eCent.txt", "r");
        FILE *eCentnew = fopen("eCenttemp.txt", "w");
        //Validate if the eCent is belongs to the device.
        size_t linecap = 0;
        char *line = NULL;
        ssize_t linelen;
        while ((linelen = getline(&line, &linecap, eCentorig)) > 0) {
            char *eCentaddr = strtok(line, "\t");
            int ownership = atoi(strtok(NULL, "\n"));
            if (strcmp(eCentaddr,eCent_address) == 0) {
                if (ownership == deviceID) {
                    //Yes, remove that, set it is used, which means success.
                    used = 1;
                } else {
                    used = -1;
                    fprintf(eCentnew, "%s\t%d\n",eCentaddr, ownership);
                }
            } else {
                fprintf(eCentnew, "%s\t%d\n",eCentaddr, ownership);
            }
        }
        fclose(eCentnew);
        fclose(eCentorig);
        //finish modifying the file.
        rename("eCenttemp.txt", "eCent.txt");
        if (used == -1) {
            return 1300;
        } else if (used == 1) { //After this is used.
            FILE *accountData = fopen("accounts.txt", "r");
            FILE *accountDataNew = fopen("account_temp.txt", "w");
            size_t linecap = 0;
            char *line = NULL;
            ssize_t linelen;
            while ((linelen = getline(&line, &linecap, accountData)) > 0) {
                int accountNumber = atoi(strtok(line, "\t"));
                char *accountPassword = strtok(NULL, "\t");
                float balance = atof(strtok(NULL, "\n"));
                if (accountNumber == account_num) {
                    float newBalance = balance + 1;
                    fprintf(accountDataNew, "%i\t%s\t%f\n", accountNumber, accountPassword, newBalance);
                } else {
                    fprintf(accountDataNew, "%i\t%s\t%f\n", accountNumber, accountPassword, balance);
                }
            }
            //close file
            fclose(accountData);
            fclose(accountDataNew);
            rename("account_temp.txt", "accounts.txt");
            //after this time the funds has been add to here and therefore return 0 means success.
            return 0;
        }
    }
    return 1400;
}

int eCent_transfer(char* eCent_address, int deviceID_orig, int deviceID_dest) {
    int return_code = 0;
    FILE *eCentdata = fopen("eCent.txt", "r");
    FILE *eCentdata_new = fopen("eCent_temp.txt", "w");
    size_t linecap = 0;
    char *line = NULL;
    ssize_t linelen;
    int match = 0;
    while ((linelen = getline(&line, &linecap, eCentdata)) > 0) {
        char *eCentaddr = strtok(line, "\t");
        int orig_belong = atoi(strtok(NULL, "\n"));
        if (strcmp(eCentaddr,eCent_address) == 0) {
            if (orig_belong == deviceID_orig) {
                match = 1;
                return_code = 0;
                fprintf(eCentdata_new, "%s\t%i\n", eCentaddr, deviceID_dest);
            } else {
                return_code = 1300;
                fprintf(eCentdata_new, "%s\t%i\n", eCentaddr, orig_belong);
            }
        } else {
            fprintf(eCentdata_new, "%s\t%i\n", eCentaddr, orig_belong);
        }
    }
    fclose(eCentdata_new);
    fclose(eCentdata);
    rename("eCent_temp.txt", "eCent.txt");
    if (match == 0) {
        return_code = 1301;
    }
    return return_code;
}
