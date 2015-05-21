/*
 Network and Security Project - Collecter Side
 data generate side.
 
 This is the simple file to generate some simple random character (crypted)
 and ask for analyser to decrypt.
 */

#include "collecter.h"

char random_data_character () {
    char charsets[] = DATA_CHARSETS;
    int initial_ran = rand();
    while (initial_ran > sizeof(charsets) - 1) {
        initial_ran = initial_ran / 10;
    }
    int index = initial_ran;
    return charsets[index];
}

void random_data(char* array) {
    for (int i = 0; i < DATA_LENGTH+1; i++) {
        array[i] = random_data_character();
        if (array[i] == '\0') {
            array[i] = random_data_character();
        }
        if (array[i] == '\0') {
            array[i] = random_data_character();
        }
        if (i == DATA_LENGTH) {
            array[i] = '\0';
        }
    }
}
