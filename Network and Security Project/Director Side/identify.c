/*
 Network and Security Project - Director Side
 Identify file.
 
 This part will available for the registration from analysis Side.
 return the result to collector.
 
 As the legal required, director must return the deviceID to collecter for security reason.
 
 for simplified this project, assume the analysis datatype is called:charToWord, and this will send from the analysis.
 */

#include "director.h"

int rec_reg(char *ana_type, int deviceID, char *IPaddress) {//receive registration
    //step one, check if the analysis list exists or not.
    int analy_exist = file_detection("analyst_list");
    if (analy_exist == 0) {
        printf("Analyst file does not exist, generating one.");
        FILE *analist = fopen("analyst_list", "w");
        fprintf(analist, "%s\t%d\t%s\n", ana_type, deviceID, IPaddress);
        fclose(analist);
    } else {
        FILE *ana_read = fopen("analyst_list", "r");
        size_t linecap = 0;
        char *line = NULL;
        ssize_t linelen;
        //load by line
        while ((linelen = getline(&line, &linecap, ana_read)) > 0) {
            char *ana_type_r = strtok(line, "\t");
            int dev_id = atoi(strtok(NULL, "\t"));
            char *ipadd = strtok(NULL, "\n");
            if (strcmp(ana_type_r, ana_type) == 0) {
                if (dev_id == deviceID) {
                    if (strcmp(ipadd, IPaddress) == 0) {
                        return 1402;
                    } else {
                        return 1405;
                    }
                }
            }
        }
        fclose(ana_read);
        FILE *ana_write = fopen("analyst_list", "a+");
        fprintf(ana_write, "%s\t%d\t%s\n", ana_type, deviceID, IPaddress);
        fclose(ana_write);
    }
    return 0;
}
