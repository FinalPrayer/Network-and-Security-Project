#Network and Security Project - Analysis Side
#Make file

C99 = gcc -std=c99
CFLAGS = -Wall -Werror -pedantic

analysis : analysis.o decode.o ana_reg.o general.o analysis_net.o analysis_ecent.o
	$(C99) $(CFLAGS) -o analysis \analysis.o decode.o ana_reg.o general.o analysis_net.o analysis_ecent.o -lm

analysis.o : analysis.c analysis.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c analysis.c

decode.o : decode.c analysis.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c decode.c

ana_reg.o : ana_reg.c analysis.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c ana_reg.c

analysis_net.o : analysis_net.c analysis.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c analysis_net.c

analysis_ecent.o : analysis_ecent.c analysis.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c analysis_eCent.c

general.o : ../Global/general.c ../Global/general.h
	$(C99) $(CFLAGS) -c ../Global/general.c
