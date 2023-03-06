all: poc.o helper.o
	$(CC) -no-pie poc.o helper.o \
		--include /usr/src/linux-hwe-5.15-headers-5.15.0-53/include/uapi/linux/netfilter/nf_tables.h \
		-lmnl -lnftnl \
		-lpthread \
		-o poc

poc.o: poc.c
	$(CC) -c -o "$@" "$<"

helper.o: helper.c
	$(CC) -c \
		-o "$@" "$<"

clean:
	rm -rf poc.o helper.o poc
