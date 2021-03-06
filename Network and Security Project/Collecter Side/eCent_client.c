//
//  eCent_client.c
//  Network and Security Project
//
//  Created by Ricardo Shura on 5/21/15.
//  Copyright (c) 2015 Ricardo Shura. All rights reserved.
//

#include "collecter.h"

int eCent_balance() {
    int balance = 0;
    int file_exists = file_detection("eCents.txt");
    if (file_exists == 0) {
        balance = 0;
    } else {
        FILE *eCent_table = fopen("eCents.txt", "r");
        size_t linecap = 0;
        char *line = NULL;
        ssize_t linelen;
        while ((linelen = getline(&line, &linecap, eCent_table)) > 0) {
            balance++;
        }
    }
    return balance;
}

int eCent_get(int volumeToGen){
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

int eCent_transfer_toAnalysis(){
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
    char *commandtype = ACT_ECENT_TRANSFER;
    //get one eCent address from the table.
    FILE *eCenttable = fopen("eCents.txt", "r");
    FILE *eCenttable_new = fopen("eCents_new.txt", "w");
    char eCent_addr_touse[ECENT_LENGTH+3];
    int switchs = 0;
    size_t linecap = 0;
    char *line = NULL;
    ssize_t linelen;
    //load by line
    while ((linelen = getline(&line, &linecap, eCenttable)) > 0) {
        if (switchs == 0) {
            FILE *used_eCent = fopen("usedeCent", "w");
            sprintf(eCent_addr_touse, "%s", strtok(line, "\n"));
            printf("eCent to use: %s\n", eCent_addr_touse);
            fprintf(used_eCent, "%s", eCent_addr_touse);
            fclose(used_eCent);
            switchs = 1;
        } else {
            fprintf(eCenttable_new,"%s", line);
        }
    }
    fclose(eCenttable);
    fclose(eCenttable_new);
    //the commandrequest. generate eCent, volume number, and the AppID.
    FILE *analysis_address = fopen("analysis_available.txt", "r");
    int counter = 0;
    int analisis_add = 0;
    while ((linelen = getline(&line, &linecap, analysis_address)) > 0) {
        if (counter == 0) {
            strtok(line, "\t");
            analisis_add = atoi(strtok(NULL, "\n"));
            counter = 1;
        }
    }
    printf("Sending eCent transfer request to the bank...\n");
    sprintf(command, "%s\t%s\t%d\t%d", commandtype, eCent_addr_touse, COLLECTER_APPID, analisis_add);
    send(connectionSocket, command, sizeof(command), 0);
    char return_code[MAX_ERROR_NUM];
    recv(connectionSocket, return_code, MAX_ERROR_NUM, 0);
    int results = atoi(return_code);
    if (results == 0) {
        rename("eCents_new.txt", "eCents.txt");
    } else {
        remove("eCents_new.txt");
    }
    return auth_code(results);
}
