#include <stdint.h>

#include <libmnl/libmnl.h>

uint8_t leak_buffer[0x100];

void hexDump(char *desc, void *addr, int len);
void send_batch(struct mnl_nlmsg_batch *batch);
static struct nftnl_table *setup_table(uint32_t family, char * table_name);
static struct nftnl_set *setup_set(uint32_t family, const char *table_name, const char *set_name);

void add_table(uint32_t family, char *table_name);
void add_set(uint32_t family, char * table_name, char * set_name);
void add_mal_set(uint32_t family, char * table_name, char * set_name);
void get_set(uint32_t family);
