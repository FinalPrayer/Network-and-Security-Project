/*
 Network and Security Project - Bank side
 This application is the bank side, which is, mostly, the server side.
 
 This is the header file, it will declare all the functions that will be use.
 
 BE WARE: This code is only available on Linux and Mac, any Unix system get count.
 GOOD BYE WINDOWS!
 */

#include "../Global/general.h"

//declare the function of another page.
extern int startup_detection();
extern int device_registration(int account_number, char* password, int deviceID);
extern int device_find(int deviceID);
int ecent_generate(int volumes, int deviceID);
extern int cash_to_eCent(int volumes, int deviceID);
extern int eCent_to_cash(char* eCent_address, int deviceID);
extern int eCent_transfer(char* eCent_address, int deviceID_orig, int deviceID_dest);
extern int network_module();
