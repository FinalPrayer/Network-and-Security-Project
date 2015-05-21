//
//  analysis.c
//  Network and Security Project
//
//  Created by Ricardo Shura on 5/21/15.
//  Copyright (c) 2015 Ricardo Shura. All rights reserved.
//

#include "analysis.h"

int main() {
    //step one: get the analysis resources online.
    decode_table_check();
    //get the ip table online.
    address_initialization();
    //after the table has been check, set up the connection from the analysis to the bank, to register the account with their deviceID.
    printf("start registering to the bank...\n");
    account_register_toBank();
    printf("\n");
    //after the account has been register to the bank, register this application to the director.
    printf("start registering to the director...\n");
    app_register_toDirector();
}
