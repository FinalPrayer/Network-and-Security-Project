/*
 Network and Security Project - General File
 
 This general header file contains some general data,
 with the general program that required to use by each program.
 */

#include <stdio.h>  //This is only the standard io library
#include <stdlib.h> //This is the standard library.
#include <string.h> //This is the string library, aims to make sure if the random generator work
#include <time.h>   //This is the time library, nah, try to set different srand each time.
//start from here are all the things that needs by networking.
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include "account.h" //account data

/*There are still some assumption required.
 assume all application has been assigned an AppID,
 which will be register to the bank, with their account.
 
 The AppID are generate with 8 digits.
 */
#define COLLECTER_APPID 45547586
#define ANALYSIS_APPID 45547585
#define BANK_APPID 15975301
#define DIRECTOR_APPID 31486252

/*
 Network Definition
 Critical things.
 
 To make sure the network can be transfer between port and port,
 make sure all applications have the same place to connect.
 */
#define NETWORK_BANK_PORT 6666
#define MAXDATASIZE 10240
#define MAX_ERROR_NUM 7

/*
 Set up some general command name for accepting and sending.
 */
#define ACT_REGISTER "register"
#define ACT_ECENT_GENERATE "generate"

#define ECENT_LENGTH 25

//Declare the essential code
extern int file_detection(const char *filename);
extern int auth_code(int authentication_result);
