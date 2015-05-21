/*
 Network and Security project
 Bank Side - Main Program
 
 This is the one to execute on the bank machine, aims act as a bank, finish the
 communication between other 3 machines, and it might be the only one that can be trust.
 
 The bank can:
 - communicate with analysis and collecter machine, so that they can register their app to the bank
 - transfer between cash flow and eCent
 - get the eCent transfer from one side to another. (The only holdings to trust.)
 */

#include "bank.h"

int main (int argc, char *argv[]) {
    //step one, startup detection.
    startup_detection();
    printf("account file initialized.\n");
    network_module();
}
