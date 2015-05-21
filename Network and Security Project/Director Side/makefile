#Network and Security Project - Director Side
#Make file

C99 = gcc -std=c99
CFLAGS = -Wall -Werror -pedantic

director : director.o identify.o director_net.o general.o
	$(C99) $(CFLAGS) -o director \director.o identify.o director_net.o general.o -lm

director.o : director.c director.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c director.c

identify.o : identify.c director.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c identify.c

director_net.o : director_net.c director.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c director_net.c

general.o : ../Global/general.c ../Global/general.h
	$(C99) $(CFLAGS) -c ../Global/general.c
