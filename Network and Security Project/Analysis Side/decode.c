/*
 Network and Security Project - Analysis Side
 Decoder Algorithm
 
 Okay, let's make this project simple as,
 the collecter send the random page.
 */

#include "analysis.h"

int decrypt_bychar(char character) {
    FILE *decryp = fopen("decrypt_temp", "a+");
    switch (character) {
        case 'a':
            fprintf(decryp, "anal");
            break;
        case 'b':
            fprintf(decryp, "boy");
            break;
        case 'c':
            fprintf(decryp, "catch");
            break;
        case 'd':
            fprintf(decryp, "drama");
            break;
        case 'e':
            fprintf(decryp, "ethical");
            break;
        case 'f':
            fprintf(decryp, "farms");
            break;
        case 'g':
            fprintf(decryp, "get");
            break;
        case 'h':
            fprintf(decryp, "hell");
            break;
        case 'i':
            fprintf(decryp, "is");
            break;
        case 'j':
            fprintf(decryp, "jesus");
            break;
        case 'k':
            fprintf(decryp, "knows");
            break;
        case 'l':
            fprintf(decryp, "learning");
            break;
        case 'm':
            fprintf(decryp, "makes");
            break;
        case 'n':
            fprintf(decryp, "new");
            break;
        case 'o':
            fprintf(decryp, "orchester");
            break;
        case 'p':
            fprintf(decryp, "pause");
            break;
        case 'q':
            fprintf(decryp, "question");
            break;
        case 'r':
            fprintf(decryp, "rising");
            break;
        case 's':
            fprintf(decryp, "shock");
            break;
        case 't':
            fprintf(decryp, "terrorism");
            break;
        case 'u':
            fprintf(decryp, "union");
            break;
        case 'v':
            fprintf(decryp, "vector");
            break;
        case 'w':
            fprintf(decryp, "warframe");
            break;
        case 'x':
            fprintf(decryp, "xylotol");
            break;
        case 'y':
            fprintf(decryp, "yelling");
            break;
        case 'z':
            fprintf(decryp, "zack");
            break;
    }
    fclose(decryp);
    return 0;
}


int decode_run(char crypted[]) {
    /*
     Okay, so this is only the decoder table to generate in the analysis table.
     a = anal   b = boy c = catch   d = drama
     e = ethical    f = farms   g = get h = hell
     i = is j = jesus   k = knows   l = learning
     m = makes  n = new o = orchester   p = pause
     q = question   r = rising  s = shock   t = terrorism
     u = union  v = vector  w = warframe    x = xylotol
     y = yelling    z = zack
     */
    printf("decrypting code...\n");
    int place = 0;
    while (1) {
        if (crypted[place] != '\0') {
            decrypt_bychar(crypted[place]);
            FILE *decryp = fopen("decrypt_temp", "a+");
            fprintf(decryp, "\n");
            fclose(decryp);
            if (crypted[place + 1] == '\0') {
                break;
            }
            place++;
        }
    }
    return 0;
}
