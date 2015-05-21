/*
 Network and Security Project - Analysis Side
 Network Module
 
 The analysis, well, sending some request to the bank, or to the director, but it is totally a server.
 It is an Analytical Server.
 */

#include "analysis.h"

int network_module(){
    int initialSocket, acceptedSocket;
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;
    initialSocket = socket(PF_INET, SOCK_STREAM, 0);
    serverAddr.sin_family = AF_INET;
    int portnum = NETWORK_ANALYSIS_ACCEPT_PORT;
    serverAddr.sin_port = htons(portnum);
    serverAddr.sin_addr.s_addr = inet_addr("0.0.0.0"); //for all range lisen.
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
    bind(initialSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
    if(listen(initialSocket,5)==0)
        printf("The analysis server has been successfully initialized.\n");
    else
        printf("Error on the server.\n");
    //accept for unlimited connections.
    while (1) {
        addr_size = sizeof serverStorage;
        acceptedSocket = accept(initialSocket, (struct sockaddr *) &serverStorage, &addr_size);
        
        char requestReceive[MAXDATASIZE];
        //receive the request from director, contains request type, eCent address, and the crypted things.
        recv(acceptedSocket, requestReceive, MAXDATASIZE, 0);
        printf("request is: %s\n", requestReceive);
        //backup
        char *commandtype = strtok(requestReceive, "\t");
        //This part is the register part.
        if (strcmp(commandtype, ACT_ANALYSIS) == 0) {
            printf("Incoming Analysis request.\n");
            //if any of their data invalid, return 400.
            char *eCent_address = strtok(NULL, "\t");
            char *crypted_data = strtok(NULL, "\n");
            //after getting the eCent address, contact the bank to reedom to money.
            int eCent_use_result = eCent_use(eCent_address);
            if (eCent_use_result == 0) {
                //if the eCent has been successfully transfer, receive data from director.
            }
        }
    }
    return 0;
}
