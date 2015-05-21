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
            char IPaddress[INET_ADDRSTRLEN];
            struct sockaddr_in* ipv4address = (struct sockaddr_in*)&serverAddr;
            int address_buffer = ipv4address->sin_addr.s_addr;
            inet_ntop( AF_INET, &address_buffer, IPaddress, INET_ADDRSTRLEN);
            //stat ask background application to work.
            int reg_result = rec_reg(analysisType, deviceID, IPaddress);
            char code[MAX_ERROR_NUM];
            sprintf(code, "%d", reg_result);
            printf("Returning registration result code: %d back to original.\n", reg_result);
            send(acceptedSocket, code, sizeof(code), 0);
        }
    }
    return 0;
}
