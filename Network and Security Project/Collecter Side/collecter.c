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
    address_initialization();
    account_register_toBank();
    int balance = eCent_balance();
    if (balance == 0) {
        printf("Balance is equal to 0, get 50 from the bank.\n");
        eCent_get(50);
    }else {
        printf("eCent Balance: %d\n", balance);
    }
    return 0;
}
