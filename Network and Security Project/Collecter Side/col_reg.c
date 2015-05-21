/*
 Network and Security Project - Collecter Side
 Registration Module
 
 This part of module will register the application to the bank.
 and save the eCent to file after returned.
 
 This part will finish after the network module finished.
 */

#include "collecter.h"

int address_initialization() {
    int bank_exist = file_detection("bankaddress");
    if (bank_exist == 0) {
        char bankadd[16];
        printf("Please enter the IP address for the bank:");
        scanf("%s", bankadd);
        FILE *bankaddress = fopen("bankaddress", "w");
        fprintf(bankaddress, "%s", bankadd);
        fclose(bankaddress);
    }
    int dire_exist = file_detection("directeraddress");
    if (dire_exist == 0) {
        char direadd[16];
        printf("Please enter the IP address for the directer:");
        scanf("%s", direadd);
        FILE *directeraddress = fopen("directeraddress", "w");
        fprintf(directeraddress, "%s", direadd);
        fclose(directeraddress);
    }
    if (bank_exist == 1 && dire_exist == 1) {
        printf("The IP address table found, skipping initialization.\n");
    } else {
        printf("The IP address has been successfully initialized.\n");
    }
    return 0;
}

int account_register_toBank(){
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
    //construct the register command to send
    char command[MAXDATASIZE];
    char *commandtype = ACT_REGISTER;
    //the commandrequest. register, with account number, account password, and the AppID.
    sprintf(command, "%s\t%d\t%s\t%d", commandtype, COLLECTER_ACCT_NUM, COLLECTER_ACCT_PASS, COLLECTER_APPID);
    send(connectionSocket, command, sizeof(command), 0);
    char return_code[MAX_ERROR_NUM];
    recv(connectionSocket, return_code, MAX_ERROR_NUM, 0);
    int results = auth_code(atoi(return_code));
    return results;
}
