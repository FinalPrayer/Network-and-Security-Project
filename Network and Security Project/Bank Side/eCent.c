/*
 Network and Security project
 Bank Side - eCent generator
 
 In this project, I assume the eCent is the currency that has release by this bank,
 so that this bank has the algorithm to genrerate and manage the eCent.
 
 To make sure the eCent can be use only on the specific verified machine, make sure the eCent
 are link to the specific device ID.
 
 REMEMBER:
 100 eCent = 1 Dollar
 */

#include "bank.h"

//In here I choose to set all the thing that might be use
#define RAND_CHARSETS "1234567890abcdefghijklmnopqrstuvwxyz"


//declare some algorithm only in eCent.
extern char random_hash_character();
extern void random_character(char* array);


//detect if the ecent file exists
int ecent_file_detect() {
    int ecent_file_exist = file_detection("ecent.txt");
    if (ecent_file_exist == 1)
        return 1;
    else
        return 0;
}

//random hash character generator - generate the random number.
char random_hash_character () {
    char charsets[] = RAND_CHARSETS;
    int initial_ran = rand();
    while (initial_ran > sizeof(charsets) - 1) {
        initial_ran = initial_ran / 10;
    }
    int index = initial_ran;
    return charsets[index];
}

//hash modifier - modify the zero hash into the random hash.
void random_hash(char* array) {
    for (int i = 0; i < ECENT_LENGTH+1; i++) {
        array[i] = random_hash_character();
        if (array[i] == '\0') {
            array[i] = random_hash_character();
        }
        if (array[i] == '\0') {
            array[i] = random_hash_character();
        }
        if (i == ECENT_LENGTH) {
            array[i] = '\0';
        }
    }
}

/*
 Assumption - assume the ecent table
 The eCent table might contain two things.
 
 column 1: the eCent ID, which is random hash.
 column 2: the ownership of the eCent.
 
 At the same time, generate a file to contain generated list of eCent,
 and gonna to return to the Collecter Side.
 */
int ecent_generate(int volumes, int deviceID) {
    //get some pre-configure
    srand((int)time(NULL));
    //step one, detect the ecent file exists or not.
    FILE *ecentdata;
    if (ecent_file_detect() == 0) {
        printf("eCent.txt file does not exist, automatic generating one.\n");
        ecentdata = fopen("eCent.txt", "w+");
    }
    else {
        printf("eCent.txt file detected. Updating.\n");
        ecentdata = fopen("eCent.txt", "a+");
    }
    //create the temp table, gonna to use to send back to client.
    FILE *tempTable;
    tempTable = fopen("temp", "w+");
    for (int i = 0; i < volumes; i++) {
        //This part is the way to generate the eCent hash.
        char ecent_hash[ECENT_LENGTH+1];
        ecent_hash[0] = '\0';
        random_hash(ecent_hash);
        fprintf(ecentdata, "%s\t%i\n", ecent_hash, deviceID);
        fprintf(tempTable, "%s\n",ecent_hash);
    }
    fclose(tempTable);
    fclose(ecentdata);
    return 0;
}
