//
//  eCent_client.c
//  Network and Security Project
//
//  Created by Ricardo Shura on 5/21/15.
//  Copyright (c) 2015 Ricardo Shura. All rights reserved.
//

#include "collecter.h"

int eCent_get(){
    //First prompt for the volumes that wants to be generate.
    char volumes[8];
    printf("Please input the volume of eCent you want to generate:");
    scanf("%s",volumes);
    int volumeToGen = atoi(volumes);
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
    char *commandtype = ACT_ECENT_GENERATE;
    //the commandrequest. generate eCent, volume number, and the AppID.
    printf("Sending request to the bank...\n");
    sprintf(command, "%s\t%d\t%d", commandtype, volumeToGen, COLLECTER_APPID);
    send(connectionSocket, command, sizeof(command), 0);
    char return_code[MAX_ERROR_NUM];
    recv(connectionSocket, return_code, MAX_ERROR_NUM, 0);
    int results = atoi(return_code);
    if (results == 0) {
        //The eCent transaction has been complete and should be start receving the eCent list.
        printf("the bank returns success message, start receiving eCents.\n");
        char eCentBuffer[ECENT_LENGTH+3];
        FILE *eCentTable = fopen("eCents.txt", "a+");
        while (1) {
            recv(connectionSocket, eCentBuffer, ECENT_LENGTH+3, 0);
            if (strcmp(eCentBuffer, "0") == 0) {
                break;
            }
            fprintf(eCentTable, "%s", eCentBuffer);
            char sen_code[3];
            strcpy(sen_code, "0");
            send(connectionSocket, sen_code, sizeof(sen_code), 0);
        }
        printf("eCent receive successfully.\n");
        fclose(eCentTable);
        return 0;
    }
    return auth_code(results);
}
