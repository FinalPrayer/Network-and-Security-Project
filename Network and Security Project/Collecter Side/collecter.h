/*
 Network and Security Project - Collecter Side
 Header File
 */

#include "../Global/general.h"

//The length and the character set for the encrypted data.
#define DATA_CHARSETS "abcdefghijklmnopqrstuvwxyz"


extern void random_data(char* array);
extern int address_initialization();
extern int account_register_toBank();
extern int eCent_get(int volumeToGen);
extern int eCent_balance();
extern int list_available();
extern int eCent_transfer_toAnalysis();
extern int request_analysis(char *cryptedContent);
