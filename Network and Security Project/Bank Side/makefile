#Network and Security Project - Bank Side
#Make file

C99 = gcc -std=c99
CFLAGS = -Wall -Werror -pedantic

bank : bank.o transaction.o account.o eCent.o bank_net.o general.o
	$(C99) $(CFLAGS) -o bank \bank.o transaction.o account.o eCent.o bank_net.o general.o -lm

bank.o : bank.c bank.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c bank.c

transaction.o : transaction.c bank.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c transaction.c

account.o : account.c bank.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c account.c

eCent.o : eCent.c bank.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c eCent.c

bank_net.o : bank_net.c bank.h ../Global/general.h ../Global/account.h
	$(C99) $(CFLAGS) -c bank_net.c

general.o : ../Global/general.c ../Global/general.h
	$(C99) $(CFLAGS) -c ../Global/general.c

clean :
	rm bank bank.o transaction.o account.o eCent.o bank_net.o general.o accounts.txt device.txt eCent.txt DO\ NOT\ MODIFY\ ANYTHING\ HERE
