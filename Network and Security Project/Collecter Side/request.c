//
//  request.c
//  Network and Security Project
//
//  Created by Ricardo Shura on 5/21/15.
//  Copyright (c) 2015 Ricardo Shura. All rights reserved.
//

#include "collecter.h"

int list_available(){
    //Second, connection.
    int connectionSocket;
    struct sockaddr_in server_address;
    socklen_t addr_size;
    connectionSocket = socket(PF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    int portnum = NETWORK_DIRECTOR_ACCEPT_PORT;
    server_address.sin_port = htons(portnum);
    //This part will take the address from file.
    FILE *bankadd = fopen("directeraddress", "r");
    char bankaddress[16];
    fgets(bankaddress, 16, bankadd);
    fclose(bankadd);
    server_address.sin_addr.s_addr = inet_addr(bankaddress);
    memset(server_address.sin_zero, '\0', sizeof(server_address.sin_zero));
    addr_size = sizeof server_address;
    connect(connectionSocket, (struct sockaddr *) &server_address, addr_size);
    //construct the eCent transfer command to send
    char command[MAXDATASIZE];
    char *commandtype = ACT_ANALYSIS_LIST;
    //the commandrequest. generate eCent, volume number, and the AppID.
    printf("Sending request to the the director...\n");
    sprintf(command, "%s\t%s", commandtype, ACT_ANALYSIS_TYPE);
    send(connectionSocket, command, sizeof(command), 0);
    char return_code[MAX_ERROR_NUM];
    recv(connectionSocket, return_code, MAX_ERROR_NUM, 0);
    int results = atoi(return_code);
    if (results == 0) {
        //The eCent transaction has been complete and should be start receving the eCent list.
        printf("the director returns success message, start receiving eCents.\n");
        char thingstoRecv[sizeof(COLLECTER_APPID)+5];
        FILE *placetoWrite = fopen("analysis_available.txt", "w+");
        while (1) {
            recv(connectionSocket, thingstoRecv, sizeof(COLLECTER_APPID)+5, 0);
            if (strcmp(thingstoRecv, "0") == 0) {
                break;
            }
            fprintf(placetoWrite, "%s\t%s\n",ACT_ANALYSIS_TYPE, thingstoRecv);
            char sen_code[3];
            strcpy(sen_code, "0");
            send(connectionSocket, sen_code, sizeof(sen_code), 0);
        }
        printf("List receive success.\n");
        fclose(placetoWrite);
        return 0;
    }
    return auth_code(results);
}
int request_analysis(char *cryptedContent){
    //Second, connection.
    int connectionSocket;
    struct sockaddr_in server_address;
    socklen_t addr_size;
    connectionSocket = socket(PF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    int portnum = NETWORK_DIRECTOR_ACCEPT_PORT;
    server_address.sin_port = htons(portnum);
    //This part will take the address from file.
    FILE *bankadd = fopen("directeraddress", "r");
    char bankaddress[16];
    fgets(bankaddress, 16, bankadd);
    fclose(bankadd);
    server_address.sin_addr.s_addr = inet_addr(bankaddress);
    memset(server_address.sin_zero, '\0', sizeof(server_address.sin_zero));
    addr_size = sizeof server_address;
    connect(connectionSocket, (struct sockaddr *) &server_address, addr_size);
    //construct the eCent transfer command to send
    char command[MAXDATASIZE];
    char *commandtype = ACT_ANALYSIS;
    //the commandrequest. generate eCent, volume number, and the AppID.
    printf("Sending analysis request to the the director...\n");
    FILE *trans_eCent = fopen("usedeCent", "r");
    char eCents[ECENT_LENGTH+1];
    fgets(eCents, ECENT_LENGTH+1, trans_eCent);
    sprintf(command, "%s\t%s", commandtype, eCents);
    send(connectionSocket, command, sizeof(command), 0);
    char return_code[MAX_ERROR_NUM];
    recv(connectionSocket, return_code, MAX_ERROR_NUM, 0);
    int results = atoi(return_code);
    if (results == 0) {
        //means the director got the message, and ask for the crypted string
        printf("director received request, sending data.\n");
        send(connectionSocket, cryptedContent, DATA_LENGTH+3, 0);
        printf("data sent, awaiting for director respond for result.\n");
        //the crypted things sent.
        char return_num[MAX_ERROR_NUM];
        recv(connectionSocket, return_num, MAX_ERROR_NUM, 0);
        int return_code = atoi(return_num);
        if (return_code == 0) {
            remove("usedeCent");
            printf("director return finished signal, ask for receving decoded file.");
            char ok[MAX_ERROR_NUM];
            sprintf(ok, "0");
            send(connectionSocket, ok, sizeof(ok), 0);
            FILE * decrypt = fopen("decrypted", "w");
            char receivedBuffer[80];
            while(1)
            {
                recv(connectionSocket, receivedBuffer, 80, 0);
                if (strcmp(receivedBuffer, "0") == 0) {
                    break;
                }
                fprintf(decrypt, "%s", receivedBuffer);
                char sen_code[3];
                strcpy(sen_code, "0");
                send(connectionSocket, sen_code, sizeof(sen_code), 0);
            }
            printf("received decoded file.\n");
            fclose(decrypt);
        }
        else {
            return auth_code(return_code);
        }
        return 0;
    }
    return auth_code(results);
}
