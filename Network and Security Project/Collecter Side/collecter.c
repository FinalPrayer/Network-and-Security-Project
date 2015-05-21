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
    printf("Please type in the action to do - [R]egister, [G]enerate:");
    char act[3];
    scanf("%s", act);
    if (strcmp(act, "r") == 0) {
        account_register_toBank();
    }
    if (strcmp(act, "g") == 0) {
        eCent_get();
    }
    return 0;
}
