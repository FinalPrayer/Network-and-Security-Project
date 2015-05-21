/*
 Network and Security Project - Analysis Side
 Decoder Algorithm
 
 Okay, let's make this project simple as,
 the collecter send the random page.
 */
#include <stdio.h>

int decode_table_init() {
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
    FILE *dectable = fopen("dectable.txt", "w+");
    fprintf(dectable, "a\tanal\n");
    fprintf(dectable, "b\tboy\n");
    fprintf(dectable, "c\tcatch\n");
    fprintf(dectable, "d\tdrama\n");
    fprintf(dectable, "e\tethical\n");
    fprintf(dectable, "f\tfarms\n");
    fprintf(dectable, "g\tget\n");
    fprintf(dectable, "h\thell\n");
    fprintf(dectable, "i\tis\n");
    fprintf(dectable, "j\tjesus\n");
    fprintf(dectable, "k\tknows\n");
    fprintf(dectable, "l\tlearning\n");
    fprintf(dectable, "m\tmakes\n");
    fprintf(dectable, "n\tnew\n");
    fprintf(dectable, "o\torchester\n");
    fprintf(dectable, "p\tpause\n");
    fprintf(dectable, "q\tquestion\n");
    fprintf(dectable, "r\trising\n");
    fprintf(dectable, "s\tshock\n");
    fprintf(dectable, "t\tterrorism\n");
    fprintf(dectable, "u\tunion\n");
    fprintf(dectable, "v\tvector\n");
    fprintf(dectable, "w\twarframe\n");
    fprintf(dectable, "x\txylotol\n");
    fprintf(dectable, "y\tyelling\n");
    fprintf(dectable, "z\tzack\n");
    return 0;
}

