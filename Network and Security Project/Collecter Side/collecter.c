/*
 Network and Security Project - Collecter Side.
 Main File
 
 The collecter can be:
 - register to the bank so that the bank can be identity this app to use eCent
 - ask for the director to get the analysis app infomation
 - transfer the data via director to analyser, and receive back
 */

#include "collecter.h"

int main(int argc, char *argv[]) {
    srand((int)time(NULL));
    address_initialization();
    account_register_toBank();
    int balance = eCent_balance();
    if (balance == 0) {
        printf("Balance is equal to 0, get 50 from the bank.\n");
        eCent_get(50);
    }else {
        printf("eCent Balance: %d\n", balance);
    }
    int available_result = list_available();
    if (available_result != 0) {
        return 1;
    }
    //generate the data.
    char rand_data[DATA_LENGTH+1];
    rand_data[0] = '\0';
    random_data(rand_data);
    //before the final step start, call the bank to transfer the eCent.
    int transfer_result = eCent_transfer_toAnalysis();
    if (transfer_result != 0) {
        return transfer_result;
    }
    printf("crypted code: %s\n", rand_data);
    int analysis_result = request_analysis(rand_data);
    if (analysis_result != 0)
    {
        return analysis_result;
    }
    return 0;
}
