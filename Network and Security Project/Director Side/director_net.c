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
                        printf("sent: %s\n", thingsToSend);
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
    }
    return 0;
}
