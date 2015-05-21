//
//  analysis_ecent.c
//  Network and Security Project
//
//  Created by Ricardo Shura on 5/21/15.
//  Copyright (c) 2015 Ricardo Shura. All rights reserved.
//

#include "analysis.h"

int eCent_use(char *eCent){
    //Second, connection.
    int connectionSocket;
    struct sockaddr_in server_address;
    socklen_t addr_size;
    connectionSocket = socket(PF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    int portnum = NETWORK_BANK_PORT;
    server_address.sin_port = htons(portnum);
    //This part will take the address from file.
    FILE *bankadd = fopen("bankaddress", "r");
    char bankaddress[16];
    fgets(bankaddress, 16, bankadd);
    server_address.sin_addr.s_addr = inet_addr(bankaddress);
    memset(server_address.sin_zero, '\0', sizeof(server_address.sin_zero));
    addr_size = sizeof server_address;
    connect(connectionSocket, (struct sockaddr *) &server_address, addr_size);
    //construct the eCent transfer command to send
    char command[MAXDATASIZE];
    char *commandtype = ACT_ECENT_REEDOM;
    //get one eCent address from the table.
    //the commandrequest. generate eCent, volume number, and the AppID.
    printf("Sending eCent reedom request to the bank...\n");
    sprintf(command, "%s\t%s\t%d", commandtype, eCent, ANALYSIS_APPID);
    send(connectionSocket, command, sizeof(command), 0);
    char return_code[MAX_ERROR_NUM];
    recv(connectionSocket, return_code, MAX_ERROR_NUM, 0);
    int results = atoi(return_code);
    printf("Bank return message: ");
    return auth_code(results);
}
