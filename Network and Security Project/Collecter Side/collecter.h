/*
 Network and Security Project - Collecter Side
 Header File
 */

#include "../Global/general.h"

//The length and the character set for the encrypted data.
#define DATA_CHARSETS "abcdefghijklmnopqrstuvwxyz"
#define DATA_LENGTH 8

extern char *data_generate ();
extern int address_initialization();
extern int account_register_toBank();
extern int eCent_get(int volumeToGen);
extern int eCent_balance();
