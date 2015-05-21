#Network and Security Project - Bank Side
#Make file

C99 = gcc -std=c99
CFLAGS = -Wall -Werror -pedantic

collecter : collecter.o data.o col_reg.o eCent_client.o general.o request.o
	$(C99) $(CFLAGS) -o collecter \collecter.o data.o col_reg.o eCent_client.o general.o request.o -lm

collecter.o : collecter.c collecter.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c collecter.c

data.o : data.c collecter.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c data.c

col_reg.o : col_reg.c collecter.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c -c col_reg.c

eCent_client.o : eCent_client.c collecter.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c eCent_client.c

request.o : request.c collecter.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c request.c

general.o : ../Global/general.c ../Global/general.h
	$(C99) $(CFLAGS) -c ../Global/general.c
