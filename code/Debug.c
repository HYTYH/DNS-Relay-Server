#include<stdio.h>
struct FLAG {
	unsigned char qr;
	unsigned char opcode;
	unsigned char aa;
	unsigned char tc;
	unsigned char rd;
	unsigned char ra;
	unsigned char z;
	unsigned char rcode;
};
struct QUE {
	unsigned char* domain;
	unsigned short type;
	unsigned short class;
};
struct RR {
	struct QUE que;
	unsigned int ttl;
	unsigned short len;
	unsigned char* resource;
	unsigned char* resource_string;/*此区域仅在class=1，type=5时有效，代表点分形式的cname回答，此时resource无效*/
};
struct DNS {
	unsigned short id;
	struct FLAG flag;
	unsigned short question_num;
	unsigned short answer_num;
	unsigned short authority_num;
	unsigned short additional_num;
	struct QUE* que;
	struct RR* ans;
	struct RR* aut;
	struct RR* add;
};
void debugDns(struct DNS dns) {
	int i, j;
	printf("------------------------------------------\n");
	printf("DNS-----ID: %.4x ------ Q,A,A,A:%d %d %d %d\n", dns.id, dns.question_num, dns.answer_num, dns.authority_num, dns.additional_num);
	for (i = 0; i < dns.question_num; i++) {
		printf("QUESTION %d:\n", i);
		puts(dns.que[i].domain);
		printf("type:%d  class:%d\n", dns.que[i].type, dns.que[i].class);
	}
	for (i = 0; i < dns.answer_num; i++) {
		printf("ANSWER %d:\n", i);
		puts(dns.ans[i].que.domain);
		printf("type:%d  class:%d\n", dns.ans[i].que.type, dns.ans[i].que.class);
		printf("resource: ttl:%d  len:%d  \n", dns.ans[i].ttl, dns.ans[i].len);
		if (dns.ans[i].que.type == 5 && dns.ans[i].que.class == 1) {/*cname*/
			printf("Cname : %s\n", dns.ans[i].resource_string);
		}
		else if (dns.ans[i].que.type == 1 && dns.ans[i].que.class == 1) {/*ipv4*/
			printf("IPv4 : %d.%d.%d.%d\n", dns.ans[i].resource[0], dns.ans[i].resource[1], dns.ans[i].resource[2], dns.ans[i].resource[3]);
		}
		else {
			for (j = 0; j < dns.ans[i].len; j++) {
				printf("%.2x ", dns.ans[i].resource[j]);
			}
		}
		printf("\n");
	}
	for (i = 0; i < dns.authority_num; i++) {
		printf("autWER %d:\n", i);
		puts(dns.aut[i].que.domain);
		printf("type:%d  class:%d\n", dns.aut[i].que.type, dns.aut[i].que.class);
		printf("resource: ttl:%d  len:%d  \n", dns.aut[i].ttl, dns.aut[i].len);
		if (dns.aut[i].que.type == 5 && dns.aut[i].que.class == 1) {/*cname*/
			printf("Cname : %s\n", dns.aut[i].resource_string);
		}
		else if (dns.aut[i].que.type == 1 && dns.aut[i].que.class == 1) {/*ipv4*/
			printf("IPv4 : %d.%d.%d.%d\n", dns.aut[i].resource[0], dns.aut[i].resource[1], dns.aut[i].resource[2], dns.aut[i].resource[3]);
		}
		else {
			for (j = 0; j < dns.aut[i].len; j++) {
				printf("%.2x ", dns.aut[i].resource[j]);
			}
		}
		printf("\n");
	}
	for (i = 0; i < dns.additional_num; i++) {
		printf("addWER %d:\n", i);
		puts(dns.add[i].que.domain);
		printf("type:%d  class:%d\n", dns.add[i].que.type, dns.add[i].que.class);
		printf("resource: ttl:%d  len:%d  \n", dns.add[i].ttl, dns.add[i].len);
		if (dns.add[i].que.type == 5 && dns.add[i].que.class == 1) {/*cname*/
			printf("Cname : %s\n", dns.add[i].resource_string);
		}
		else if (dns.add[i].que.type == 1 && dns.add[i].que.class == 1) {/*ipv4*/
			printf("IPv4 : %d.%d.%d.%d\n", dns.add[i].resource[0], dns.add[i].resource[1], dns.add[i].resource[2], dns.add[i].resource[3]);
		}
		else {
			for (j = 0; j < dns.add[i].len; j++) {
				printf("%.2x ", dns.add[i].resource[j]);
			}
		}
		printf("\n");
	}
	printf("------------------------------------------\n");
}
void debugDns2(unsigned char* dns, int len) {

	int i, j;
	printf("HEAD:\n");
	for (i = 0; i < 12; i++) {
		printf("%.2x ", dns[i]);
	}
	printf("\nIN:\n");
	for (i = 12, j = 0; i < len; i++) {
		printf("%.2x ", dns[i]);
		j++;
		if (j >= 8) {
			j = 0;
			printf("\n");
		}
	}
	printf("\n\nEND!\n");
}