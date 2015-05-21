//
//  director.c
//  Network and Security Project
//
//  Created by Ricardo Shura on 5/21/15.
//  Copyright (c) 2015 Ricardo Shura. All rights reserved.
//

#include "director.h"

int network_module(){
    int initialSocket, acceptedSocket;
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;
    initialSocket = socket(PF_INET, SOCK_STREAM, 0);
    serverAddr.sin_family = AF_INET;
    int portnum = NETWORK_DIRECTOR_ACCEPT_PORT;
    serverAddr.sin_port = htons(portnum);
    serverAddr.sin_addr.s_addr = inet_addr("0.0.0.0"); //for all range lisen.
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
    bind(initialSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
    if(listen(initialSocket,5)==0)
        printf("The director server has been successfully initialized.\n");
    else
        printf("Error on the server.\n");
    //accept for unlimited connections.
    while (1) {
        addr_size = sizeof serverStorage;
        acceptedSocket = accept(initialSocket, (struct sockaddr *) &serverStorage, &addr_size);
        
        char requestReceive[MAXDATASIZE];
        recv(acceptedSocket, requestReceive, MAXDATASIZE, 0);
        //so far, the requestReceive contains the whole request from the server, therefore analysis is the only job to do.
        //backup
        char *commandtype = type_identify(requestReceive);
        //This part is the register part.
        if (strcmp(commandtype, ACT_REGISTER) == 0) {
            printf("Incoming register request transmission.\n");
            //if any of their data invalid, return 400.
            int accountNumber = atoi(strtok(NULL, "\t"));
            if (accountNumber == 0) {
                char *code = "400";
                send(acceptedSocket, code, sizeof(code), 0);
                continue;
            }
            char *password = strtok(NULL, "\t");
            if (password == NULL) {
                char *code = "400";
                send(acceptedSocket, code, sizeof(code), 0);
                continue;
            }
            int deviceID = atoi(strtok(NULL, "\n"));
            if (deviceID == 0) {
                char *code = "400";
                send(acceptedSocket, code, sizeof(code), 0);
                continue;
            }
            int register_result = device_registration(accountNumber, password, deviceID);
            char code[MAX_ERROR_NUM];
            sprintf(code, "%d", register_result);
            printf("Returning registration result code: %d back to original.\n", register_result);
            send(acceptedSocket, code, sizeof(code), 0);
        }
        //here is the way to receive command and generate eCent. hmmmm.
        else if (strcmp(commandtype, ACT_ECENT_GENERATE) == 0) {
            printf("Incoming eCent generate request transmission.\n");
            int volumes = atoi(strtok(NULL, "\t"));
            if (volumes == 0) {
                char *code = "400";
                send(acceptedSocket, code, sizeof(code), 0);
                continue;
            }
            int deviceID = atoi(strtok(NULL, "\n"));
            if (deviceID == 0) {
                char *code = "400";
                send(acceptedSocket, code, sizeof(code), 0);
                continue;
            }
            int convert_result = cash_to_eCent(volumes, deviceID);
            if (convert_result == 0) {
                printf("Returning eCent success message back to client to open eCent transfer.\n");
                char code[MAX_ERROR_NUM];
                sprintf(code, "%d", convert_result);
                send(acceptedSocket, code, sizeof(code), 0);
                //after the success code has been opened, start the eCent transfer.
                FILE *eCentTrans = fopen("temp", "r");
                size_t linecap = 0;
                char *line = NULL;
                ssize_t linelen;
                //load by line
                printf("start transferring eCent list to client...\n");
                while ((linelen = getline(&line, &linecap, eCentTrans)) > 0) {
                    //To make sure sending and receiving would not being error, try to use another character to send.
                    char buffer2[ECENT_LENGTH+3];
                    strcpy(buffer2, line);
                    send(acceptedSocket, buffer2, ECENT_LENGTH+3, 0);
                    char rec_code[3];
                    recv(acceptedSocket, rec_code, 3, 0);
                }
                send(acceptedSocket, code, sizeof(code), 0);
                printf("eCent transfer completed.\n");
            } else {
                printf("Returning eCent error code %d back to client to open eCent transfer.", convert_result);
                char code[MAX_ERROR_NUM];
                sprintf(code, "%d", convert_result);
                send(acceptedSocket, code, sizeof(code), 0);
            }
        }
    }
    return 0;
}
