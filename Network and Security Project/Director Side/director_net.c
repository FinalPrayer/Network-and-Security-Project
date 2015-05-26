#include "director.h"

int ana_init() {
    int ana_exist = file_detection("analysisaddress");
    if (ana_exist == 0) {
        char anaadd[16];
        printf("Please enter the IP address for the analysis:");
        scanf("%s", anaadd);
        FILE *analysisaddress = fopen("analysisaddress", "w");
        fprintf(analysisaddress, "%s", anaadd);
        fclose(analysisaddress);
    }
    if (ana_exist == 1) {
        printf("The IP address table found, skipping initialization.\n");
    } else {
        printf("The IP address has been successfully initialized.\n");
    }
    return 0;
}

int send_toAnalysis(char *eCent_add, char *cryptedData) {
    //Second, connection.
    int connectionSocket;
    struct sockaddr_in server_address;
    socklen_t addr_size;
    connectionSocket = socket(PF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    int portnum = NETWORK_ANALYSIS_ACCEPT_PORT;
    server_address.sin_port = htons(portnum);
    //This part will take the address from file.
    FILE *analadd = fopen("analysisaddress", "r");
    char analysisaddress[16];
    fgets(analysisaddress, 16, analadd);
    server_address.sin_addr.s_addr = inet_addr(analysisaddress);
    memset(server_address.sin_zero, '\0', sizeof(server_address.sin_zero));
    addr_size = sizeof server_address;
    connect(connectionSocket, (struct sockaddr *) &server_address, addr_size);
    //construct the eCent transfer command to send
    char command[MAXDATASIZE];
    char *commandtype = ACT_ANALYSIS;
    //the commandrequest. generate eCent, volume number, and the AppID.
    printf("Forwarding analysis request to the analysis.\n");
    sprintf(command, "%s\t%s\t%s", commandtype, eCent_add, cryptedData);
    send(connectionSocket, command, sizeof(command), 0);
    //receive the code to see if the decode has been success or not.
    char return_code[MAX_ERROR_NUM];
    recv(connectionSocket, return_code, MAX_ERROR_NUM, 0);
    int return_num = atoi(return_code);
    if (return_num == 0) {
        printf("received finished signal, start receiving decoded file.\n");
        char ok[MAX_ERROR_NUM];
        FILE *temp = fopen("temp", "w");
        sprintf(ok, "0");
        send(connectionSocket, ok, sizeof(ok), 0);
        char receivedBuffer[MAXDATASIZE];
        while(1)
        {
            recv(connectionSocket, receivedBuffer, MAXDATASIZE, 0);
            if (strcmp(receivedBuffer, "0") == 0) {
                break;
            }
            fprintf(temp, "%s", receivedBuffer);
            char sen_code[3];
            strcpy(sen_code, "0");
            send(connectionSocket, sen_code, sizeof(sen_code), 0);
        }
        printf("received decoded file.\n");
        fclose(temp);
    } else {
        return return_num;
    }
    return 0;
}

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
        char *commandtype = strtok(requestReceive, "\t");
        //This part is the register from analysis.
        //the structure of the request is: type \t analysistype \t deviceID
        if (strcmp(commandtype, ACT_REGISTER) == 0) {
            printf("Incoming application registration request.\n");
            char *analysisType = strtok(NULL, "\t");
            if (analysisType == NULL) {
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
            //get the IP address of the socket.
            FILE *analyadd = fopen("analysisaddress", "r");
            char analysisaddress[16];
            fgets(analysisaddress, 16, analyadd);
            //stat ask background application to work.
            int reg_result = rec_reg(analysisType, deviceID, analysisaddress);
            char code[MAX_ERROR_NUM];
            sprintf(code, "%d", reg_result);
            printf("Returning registration result code: %d back to original.\n", reg_result);
            send(acceptedSocket, code, sizeof(code), 0);
        }
        //part for the analysis listing.
        else if (strcmp(commandtype, ACT_ANALYSIS_LIST) == 0) {
            printf("Incoming analysis availability listing request.\n");
            char * analysis_type = strtok(NULL, "\n");
            if (analysis_type == NULL) {
                char *code = "400";
                send(acceptedSocket, code, sizeof(code), 0);
                continue;
            }
            int anal_result = reg_check(analysis_type);
            if (anal_result == 0) {
                printf("Returning eCent success message back to client to open eCent transfer.\n");
                char code[MAX_ERROR_NUM];
                sprintf(code, "%d", anal_result);
                send(acceptedSocket, code, sizeof(code), 0);
                //after the success code has been opened, start the eCent transfer.
                FILE *analList = fopen("analyst_list", "r");
                size_t linecap = 0;
                char *line = NULL;
                ssize_t linelen;
                while ((linelen = getline(&line, &linecap, analList)) > 0) {
                    //To make sure sending and receiving would not being error, try to use another character to send.
                    char *analtype = strtok(line, "\t");
                    if (strcmp(analtype, analysis_type) == 0) {
                        int deviID = atoi(strtok(NULL, "\t"));
                        char thingsToSend[9];
                        sprintf(thingsToSend,"%i", deviID);
                        send(acceptedSocket, thingsToSend, sizeof(thingsToSend), 0);
                        char rec_code[3];
                        recv(acceptedSocket, rec_code, 3, 0);
                    }
                }
                send(acceptedSocket, code, sizeof(code), 0);
                fclose(analList);
                //load by line
                printf("start transferring analysis available list to client...\n");
                send(acceptedSocket, code, sizeof(code), 0);
                printf("analysis available transfer completed.\n");
            } else {
                printf("return error code: %d to the client.\n", anal_result);
                char code_return[MAX_ERROR_NUM];
                sprintf(code_return, "%d", anal_result);
                send(acceptedSocket, code_return, sizeof(code_return), 0);
            }
            
        }
        //This part is the final part: receive the data from collecter and communicate with the analysis.
        else if (strcmp(commandtype, ACT_ANALYSIS) == 0) {
            //step one, take the eCent from the list.
            printf("received analysis request.\n");
            char *eCentAdd = strtok(NULL, "\t");
            char *crypted = strtok(NULL, "\n");
            if (strcmp(eCentAdd, "") != 0 && strcmp(crypted, "") != 0) {
                //got the eCent data, tell collecter "I've got the message" and ask for the crypted data.
                char received[MAX_ERROR_NUM];
                strcpy(received, "0");
                printf("received crypted data: %s\n",crypted);
                //okay, now we have the crypted data, the eCent, and the request. time to ask the analysis to work.
                //things has been received.
                int communicate_result = send_toAnalysis(eCentAdd, crypted);
                if (communicate_result == 0) {
                    //received decoded data, send back to the
                    printf("forwarding decrypted file to collecter.\n");
                    send(acceptedSocket, received, sizeof(received), 0);
                    char ok[MAX_ERROR_NUM];
                    recv(acceptedSocket, ok, MAX_ERROR_NUM, 0);
                    FILE * decoded = fopen("temp", "r");
                    size_t linecap = 0;
                    char *line = NULL;
                    ssize_t linelen;
                    //load by line
                    while ((linelen = getline(&line, &linecap, decoded)) > 0) {
                        char buffer[MAXDATASIZE];
                        strcpy(buffer, line);
                        send(acceptedSocket, buffer, MAXDATASIZE, 0);
                        char rec_code[3];
                        recv(acceptedSocket, rec_code, 3, 0);
                    }
                    send(acceptedSocket, ok, sizeof(ok), 0);
                    printf("decoded file has been successfully sent back to collecter.\n");
                    remove("temp");

                }
                else {
                    char error_code[MAX_ERROR_NUM];
                    sprintf(error_code,"%d", communicate_result);
                    send(acceptedSocket, error_code, sizeof(error_code), 0);
                }
            }
        }
        printf("\n");
    }
    return 0;
}
