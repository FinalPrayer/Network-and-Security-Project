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
    }
    return 0;
}
