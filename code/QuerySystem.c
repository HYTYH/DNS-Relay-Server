#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<windows.h>
#include<time.h>
#define CNAME_IP_HASH 128
#define DOMAIN_CNAME_HASH 128

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
	unsigned char* resource_string;/*���������class=1��type=5ʱ��Ч����������ʽ��cname�ش𣬴�ʱresource��Ч*/
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
struct DOMAIN_CNAME_RECORD {
	struct DOMAIN_CNAME_RECORD* next;
	unsigned char* domain;
	unsigned char* cname;
	int ttl;
};
struct CNAME_IP_RECORD {
	struct CNAME_IP_RECORD* next;
	unsigned char* cname;
	unsigned char** ip;
	int* ip_ttl;
	int flag;
	int ip_num;
};
struct CNAME_IP_RECORD** ip_record;
struct DOMAIN_CNAME_RECORD** cname_record;
int ip_hash, cname_hash;
extern int Debug_Level;
extern char Set_File[64];
struct DNS presets;/*Ԥ���DNS��Ϣ*/
static void addAnswer(struct DNS* dns, struct RR add) {/*��add����Դ��������д��dns��ans�����У�����������Դ���������Լ��ڴ�����*/
	
	/*�޸Ŀռ��С*/
	struct RR* temp;
	temp = realloc(dns->ans, sizeof(struct RR) * (dns->answer_num + (long long)1));
	if (temp == NULL) {
		printf("realloc failed!\n");
		exit(1);
	}
	dns->ans = temp;
	/*�����ֵ*/
	dns->ans[dns->answer_num] = add;/*��ttl��len��������*/
	dns->ans[dns->answer_num].que.domain = (unsigned char*)malloc(sizeof(char) * (strlen(add.que.domain) + 1));
	strcpy(dns->ans[dns->answer_num].que.domain, add.que.domain);
	if (dns->ans[dns->answer_num].que.class == 1 && dns->ans[dns->answer_num].que.type == 5) {/*cnameӦ��string������Ч*/
		dns->ans[dns->answer_num].resource_string = (unsigned char*)malloc(sizeof(char) * (strlen(add.resource_string) + 1));
		strcpy(dns->ans[dns->answer_num].resource_string, add.resource_string);
		dns->ans[dns->answer_num].resource = NULL;
	}
	else if (dns->ans[dns->answer_num].que.class == 1 && dns->ans[dns->answer_num].que.type == 1) {/*ipӦ��resource��Ч*/
		dns->ans[dns->answer_num].resource = (unsigned char*)malloc(sizeof(char) * (add.len));
		memcpy(dns->ans[dns->answer_num].resource, add.resource, add.len);
		dns->ans[dns->answer_num].resource_string = NULL;
	}
	else {
		printf("DEBUG:add not cname nor ipv4 ,wrong!\n"); exit(1);/*����cnameҲ����ip*/
	}
	/*�޸������ֶ�*/
	dns->answer_num += 1;
}
static int hashCalculate(unsigned char* src, int hashnum) {/*����src����Ӧ�ַ�����domain-ipת�������ж�Ӧ��ϣֵ�����ڶ�λ��¼��λ��*/
	int i, ret;
	int len = strlen(src);
	if (len <= 0) {
		return 0;
	}
	for (i = 0, ret = 0; i < len; i++) {
		ret += src[i];
	}
	return (ret * 77777) % hashnum;
}
static void freeIpRecord(struct CNAME_IP_RECORD* record, int mode) {/*���CNAME-ip��һ����¼��mode����ģʽ�����Ϊ0������ȫ�ͷţ������ͷ�cname����*/
	int i;
	for (i = 0; i < record->ip_num; i++) {
		free(record->ip[i]);
	}
	free(record->ip);
	free(record->ip_ttl);
	record->ip_ttl = NULL;
	record->ip = NULL;
	record->ip_num = 0;
	record->flag = 0;
	if (mode == 0) {/*��ȫ�ͷ�*/
		free(record->cname); record->cname = NULL;
	}
}
static void addCnameIp(struct DNS dns) {/*��dns����������cname-ip�Ļش������ת���ļ�¼��*/
	int i, time, iplen, cnamelen, hash, flag;
	struct CNAME_IP_RECORD* current;
	unsigned char** temp;
	int* temp2;
	iplen = 4;
	time = clock();
	
	for (i = 0; i < dns.answer_num; i++) {
		if (dns.ans[i].que.type == 1 && dns.ans[i].que.class == 1) {/*��IPv4��Cname-IPӦ��*/
			cnamelen = strlen(dns.ans[i].que.domain);
			hash = hashCalculate(dns.ans[i].que.domain, ip_hash);
			for (current = ip_record[hash]->next, flag = 0; current != NULL; current = current->next) {
				if (strcmp(current->cname, dns.ans[i].que.domain) == 0) {/*����ƥ���¼�������ip*/
					if (current->flag == 0) {
						freeIpRecord(current, 1);/*�Ȱ�ԭ�����ͷ���,mode=1���������domain����*/
						current->flag = 1;
					}
					current->ip_num += 1;/*��һ����¼*/
					temp = (unsigned char**)realloc(current->ip, sizeof(unsigned char*) * current->ip_num);/*����ռ�*/
					if (temp != NULL) {/*����ɹ�*/
						current->ip = (unsigned char**)temp;
					}
					else {/*����ʧ��*/
						printf("error!"); exit(1);
					}
					current->ip[current->ip_num - 1] = (unsigned char*)malloc(sizeof(unsigned char) * iplen);/*����һ��ip����4���ֽڿռ�*/
					temp2 = (int*)realloc(current->ip_ttl, sizeof(int) * current->ip_num);
					if (temp2 != NULL) {
						current->ip_ttl = (int*)temp2;
					}
					else {
						printf("error!"); exit(1);

					}
					current->ip_ttl[current->ip_num - 1] = time + 1000 * dns.ans[i].ttl;
					memcpy(current->ip[current->ip_num - 1], dns.ans[i].resource, iplen);
					flag = 1; break;/*�鵽�ˣ�����*/
				}
			}
			if (flag == 0) {/*û�鵽��ͷ��*/
				current = (struct CNAME_IP_RECORD*)malloc(sizeof(struct CNAME_IP_RECORD));
				current->cname = (unsigned char*)malloc(sizeof(char) * (strlen(dns.ans[i].que.domain) + 1));
				strcpy(current->cname, dns.ans[i].que.domain);
				current->ip_num = 1;
				current->ip = (unsigned char**)malloc(sizeof(unsigned char*) * current->ip_num);
				current->ip[current->ip_num - 1] = (unsigned char*)malloc(sizeof(unsigned char) * iplen);
				current->ip_ttl = (int*)malloc(sizeof(int) * current->ip_num);
				current->ip_ttl[current->ip_num - 1] = time + 1000 * dns.ans[i].ttl;
				memcpy(current->ip[current->ip_num - 1], dns.ans[i].resource, iplen);
				current->flag = 1;/*�����Ǳ��β�������ӵģ������������������Ѵ��ڵģ�ֻ���*/
				current->next = ip_record[hash]->next;
				ip_record[hash]->next = current;
			}
		}
	}
	for (i = 0; i < dns.answer_num; i++) {
		if (dns.ans[i].que.type == 1 && dns.ans[i].que.class == 1) {/*��IPv4��Cname-IPӦ��*/
			for (current = ip_record[hash]->next, flag = 0; current != NULL; current = current->next) {
				if (strcmp(current->cname, dns.ans[i].que.domain) == 0) {
					current->flag = 0; break;
				}
			}
		}
	}
}
static void addDomainCname(struct DNS dns) {/*��dns����������domian-cname�Ļش������ת���ļ�¼��*/
	int i, time, domainlen, cnamelen, hash, flag;
	struct DOMAIN_CNAME_RECORD* current;
	time = clock();
	
	for (i = 0; i < dns.answer_num; i++) {
		if (dns.ans[i].que.type == 5 && dns.ans[i].que.class == 1) {/*��IPv4��CnameӦ��*/
			domainlen = strlen(dns.ans[i].que.domain);
			cnamelen = strlen(dns.ans[i].resource_string);
			hash = hashCalculate(dns.ans[i].que.domain, cname_hash);/*�����Ӧhash*/
			for (current = cname_record[hash]->next, flag = 0; current != NULL; current = current->next) {/*�ҵ�hash��Ӧ��¼������㣬��ʼ����*/
				if (time < current->ttl && strcmp(current->domain, dns.ans[i].que.domain) == 0) {/*�����ҵ��˻�û�й��ڵ���ͬ��¼*/
					if (strcmp(current->cname, dns.ans[i].resource_string) != 0) {/*��Դ��¼���ֲ�һ������Ҫ����*/
						free(current->cname);
						current->cname = (unsigned char*)malloc((sizeof(char)) * (cnamelen + 1));/*���·����С*/
						strcpy(current->cname, dns.ans[i].resource_string);/*���µ���Դ���ֿ�������¼��*/
					}
					current->ttl = time + 1000 * dns.ans[i].ttl;/*����ttl*/
					flag = 1; break;/*����flag��ʾ����ʾ��¼�Ѵ��ڲ����Ѿ�������ɣ���ѭ��*/
				}
			}
			if (flag == 0) {/*����û�ҵ���û���£���ôͷ��ü�¼*/
				current = (struct DOMAIN_CNAME_RECORD*)malloc(sizeof(struct DOMAIN_CNAME_RECORD));
				current->ttl = time + 1000 * dns.ans[i].ttl;/*����ttl*/
				current->next = cname_record[hash]->next;/*next�ֶθ�ֵ*/
				current->domain = (unsigned char*)malloc(domainlen + 1);/*domain��cname�ֶη���ռ䣬�����ַ���*/
				current->cname = (unsigned char*)malloc(cnamelen + 1);
				strcpy(current->domain, dns.ans[i].que.domain);
				strcpy(current->cname, dns.ans[i].resource_string);
				cname_record[hash]->next = current;/*ͷָ��ָ���·���Ŀռ�ĵ�ַ*/
			}
			/*�������*/
		}
	}
}
static struct DOMAIN_CNAME_RECORD* queryCname(unsigned char* src) {/*��ѯsrc��Ӧ�ַ�����cname����ѯ�ɹ��򷵻ؼ�¼��Ӧ���ݵĵ�ַ�����ʧ�ܣ��޼�¼����ڣ��򷵻�NULL*/
	struct DOMAIN_CNAME_RECORD* current;
	int time, hash;
	time = clock();
	hash = hashCalculate(src, cname_hash);
	for (current = cname_record[hash]->next; current != NULL; current = current->next) {
		if (time < current->ttl && strcmp(current->domain, src) == 0) {
			return current;
		}
	}
	return NULL;
}
static struct CNAME_IP_RECORD* queryIp(unsigned char* src) {/*��ѯsrc��Ӧ�ַ�����ip����ѯ�ɹ��򷵻ؼ�¼��Ӧ���ݵĵ�ַ�����ʧ�ܣ��޼�¼����ڣ��򷵻�NULL*/
	struct CNAME_IP_RECORD* current;
	int time, hash, i;
	time = clock();
	hash = hashCalculate(src, ip_hash);
	for (current = ip_record[hash]->next; current != NULL; current = current->next) {
		if (strcmp(current->cname, src) == 0) {
			for (i = 0; i < current->ip_num; i++) {
				if (current->ip_ttl[i] <= time) {/*�й��ڵ�*/
					return NULL;
				}
			}
			return current;
		}
	}
	return NULL;
}
void debugDomainCname(void) {
	int i;
	struct DOMAIN_CNAME_RECORD* current;
	printf("DEBUG:Domian->Cname:  hash:%d\n", cname_hash);
	printf("DEBUG:time : %d\n", clock());
	for (i = 0; i < cname_hash; i++) {
		printf("DEBUG:cname hash=%d:\n info:", i);
		for (current = cname_record[i]->next; current != NULL; current = current->next) {
			printf("%s -> %s  TTL:%d\n", current->domain, current->cname, current->ttl);
		}
		printf("\n");
	}
	printf("DEBUG:Domain->Cname debuged!!!\n");
}
void debugCnameIp(void) {
	int i, j;
	struct CNAME_IP_RECORD* current;
	printf("DEBUG:Cname->Ip:  hash:%d\n", ip_hash);
	printf("DEBUG:time : %d\n", clock());
	for (i = 0; i < ip_hash; i++) {
		printf("DEBUG:ip hash=%d  info:\n", i);
		for (current = ip_record[i]->next; current != NULL; current = current->next) {
			printf("%s  ipnum:%d\n", current->cname, current->ip_num);
			for (j = 0; j < current->ip_num; j++) {
				printf("%d.%d.%d.%d  TTL: %d\n", current->ip[j][0], current->ip[j][1], current->ip[j][2], current->ip[j][3], current->ip_ttl[j]);
			}
		}
		printf("\n");
	}
	printf("DEBUG:Domain->Cname debuged!!!\n");
}
void recordInit(void) {/*domain-ipת�����ܵĳ�ʼ��*/
	int i;
	/*���η���ռ������*/
	ip_hash = CNAME_IP_HASH;
	cname_hash = DOMAIN_CNAME_HASH;
	cname_record = (struct DOMAIN_CNAME_RECORD**)malloc(sizeof(struct DOMAIN_CNAME_RECORD*) * cname_hash);
	ip_record = (struct CNAME_IP_RECORD**)malloc(sizeof(struct CNAME_IP_RECORD*) * ip_hash);
	for (i = 0; i < cname_hash; i++) {
		cname_record[i] = (struct DOMAIN_CNAME_RECORD*)malloc(sizeof(struct DOMAIN_CNAME_RECORD));
		cname_record[i]->cname = NULL;
		cname_record[i]->domain = NULL;
		cname_record[i]->next = NULL;
		cname_record[i]->ttl = 0;
	}
	for (i = 0; i < ip_hash; i++) {
		ip_record[i] = (struct CNAME_IP_RECORD*)malloc(sizeof(struct CNAME_IP_RECORD));
		ip_record[i]->cname = NULL;
		ip_record[i]->flag = 0;
		ip_record[i]->ip = NULL;
		ip_record[i]->ip_num = 0;
		ip_record[i]->ip_ttl = NULL;
		ip_record[i]->next = NULL;
	}
	/*��ʼ����Ԥ����Ϣ*/
	FILE* fd;
	unsigned char buff[256];
	int buff2[4];
	struct RR temp;

	fd = freopen(Set_File, "r", stdin);
	memset(&presets, 0, sizeof(struct DNS));
	memset(&temp, 0, sizeof(struct RR));
	temp.que.domain = (unsigned char*)malloc(sizeof(char) * 256);
	temp.resource = (unsigned char*)malloc(sizeof(char) * 4);
	temp.len = 4;
	temp.ttl = 20000;
	temp.que.class = temp.que.type = 1;
	if (fd == NULL) {/*û�ҵ�Ԥ���ļ�*/
		if (Debug_Level >= 1) {
			printf("Not found FILE\n");
		}
	}
	else {
		if (Debug_Level >= 1) {
			printf("\"%s\" found!\n", Set_File);/*�ҵ�Ԥ���ļ�*/
		}
		while (scanf("%s %d.%d.%d.%d\n", buff, buff2, buff2 + 1, buff2 + 2, buff2 + 3) != EOF) {
			strcpy(temp.que.domain, buff);
			temp.resource[0] = buff2[0]; temp.resource[1] = buff2[1]; temp.resource[2] = buff2[2]; temp.resource[3] = buff2[3];
			addAnswer(&presets, temp);/*��Ԥ���ļ��е�cname-ip����뻺��*/
		}
		addCnameIp(presets);
	}
	free(temp.que.domain); free(temp.resource);
	freopen("CON", "r", stdin);
}
int queryDomainIp(struct DNS* dst, struct DNS src) {
	int i, time;
	struct RR temp;
	struct DOMAIN_CNAME_RECORD* cname;
	struct CNAME_IP_RECORD* ip;
	unsigned char* que;

	memcpy(dst, &src, sizeof(struct DNS));
	dst->answer_num = dst->authority_num = dst->additional_num = 0;
	dst->flag.aa = 0;/*����Ȩ*/
	dst->flag.ra = 1;/*�ɵݹ�*/
	dst->flag.tc = 0;/*���ض�*/
	dst->flag.qr = 1;/*��Ӧ��*/
	dst->que = (struct QUE*)malloc(sizeof(struct QUE) * dst->question_num);
	for (i = 0; i < dst->question_num; i++) {
		dst->que[i].domain = (unsigned char*)malloc(sizeof(char) * (strlen(src.que[i].domain) + 1));
		dst->que[i].class = src.que[i].class;
		dst->que[i].type = src.que[i].type;
		strcpy(dst->que[i].domain, src.que[i].domain);
	}
	time = clock();

	for (i = 0; i < src.question_num; i++) {
		if (src.que[i].type == 1 && src.que[i].class == 1) {/*ipv4��domain-ip��ѯ*/
			for (cname = queryCname(src.que[i].domain), que = src.que[i].domain; 1;) {
				//printf("DEBUG:CNAME:%s\n", que);
				if (cname != NULL) {
					temp.que.class = 1; temp.que.type = 5;
					temp.que.domain = (unsigned char*)malloc(sizeof(char) * (strlen(que) + 1));
					temp.resource_string = (unsigned char*)malloc(sizeof(char) * (strlen(cname->cname) + 1));
					strcpy(temp.que.domain, que);
					temp.len = 4;
					strcpy(temp.resource_string, cname->cname);
					temp.resource = NULL;
					temp.ttl = 1 + (cname->ttl - time) / 1000;
					addAnswer(dst, temp);
					que = cname->cname;
					free(temp.que.domain);
					free(temp.resource_string);
					cname = queryCname(que);
				}
				else {
					break;
				}
			}
			/*cname�����ˣ���ip*/
			//printf("DEBUG:Cname query finished!\n");
			ip = queryIp(que);
			if (ip == NULL) {
				//printf("DEBUG:ip query failed! cname:%s \n", que);
				return 0;/*��ѯʧ�ܣ�����Ip�й��ڵģ���ʱ���ϼ���������ѯ*/
			}
			else {/*�鵽�ˣ�û����*/
				//printf("DEBUG:ip query succ! cname:%s\n",que);
				temp.que.class = 1; temp.que.type = 1;
				temp.que.domain = (unsigned char*)malloc(sizeof(char) * (strlen(que) + 1));
				strcpy(temp.que.domain, que);
				temp.resource_string = NULL;
				temp.resource = (unsigned char*)malloc(sizeof(char) * 4);
				temp.len = 4;
				for (i = 0; i < ip->ip_num; i++) {/*���ν�cname-ip�������dst*/
					memcpy(temp.resource, ip->ip[i], 4);
					temp.ttl = 1 + (ip->ip_ttl[i] - time) / 1000;
					if (temp.resource[0] == 0 && temp.resource[1] == 0 && temp.resource[2] == 0 && temp.resource[3] == 0) {
						dst->flag.rcode = 3;
					}
					addAnswer(dst, temp);

					//printf("DEBUG:ip:%ud.%ud.%ud.%ud TTL:%d\n", temp.resource[0], temp.resource[1], temp.resource[2], temp.resource[3], temp.ttl);
				}
				free(temp.que.domain); free(temp.resource);
			}
		}
		else {
			return 0;
		}
	}
	return 1;
}
void domainIpRecordFlush(void) {
	int i, j, k, count, flag;
	int time = clock();
	struct DOMAIN_CNAME_RECORD* ptr1, * temp1;
	struct CNAME_IP_RECORD* ptr2, * temp2;
	for (i = 0, count = 0; i < cname_hash; i++) {
		for (ptr1 = cname_record[i]; ptr1->next != NULL;) {
			if (time >= ptr1->next->ttl) {
				temp1 = ptr1->next->next;
				free(ptr1->next->cname); free(ptr1->next->domain); free(ptr1->next);
				ptr1->next = temp1;
			}
			else {
				ptr1 = ptr1->next;
				count++;
			}
		}
	}
	if (Debug_Level >= 2) {
		printf("Time:%.3lf ", ((double)clock()) / 1000.0);
		printf("DEBUG:Cname record flushed! average cost:%lf  \n", ((double)count) / cname_hash);
	}
	/*
	if (((double)count) / cname_hash > CNAME_MAX_OCCUPATION) {
		cname_hash *= 2;
		temp1 = (struct DOMAIN_CNAME_RECORD*)realloc(cname_record, sizeof(struct DOMAIN_CNAME_RECORD*) * cname_hash);
		if (temp1 != NULL) {
			cname_record = (struct DOMAIN_CNAME_RECORD**)temp1;
			printf("DEBUG:cname_hash increased! new hash: %d\n", cname_hash);
		}
		else {
			printf("DEBUG:realloc failed ,exit\n"); exit(1);
		}
	}
	if (((double)count) / cname_hash < CNAME_MIN_OCCUPATION && cname_hash >= 120) {
		cname_hash /= 2;
		temp1 = (struct DOMAIN_CNAME_RECORD*)realloc(cname_record, sizeof(struct DOMAIN_CNAME_RECORD*) * cname_hash);
		if (temp1 != NULL) {
			cname_record = (struct DOMAIN_CNAME_RECORD**)temp1;
			printf("DEBUG:cname_hash decreased! new hash: %d\n", cname_hash);
		}
		else {
			printf("DEBUG:realloc failed(cname) ,exit\n"); exit(1);
		}
	}*/
	for (i = 0, count = 0; i < ip_hash; i++) {
		for (ptr2 = ip_record[i]; ptr2->next != NULL;) {
			for (j = 0, flag = 0; j < ptr2->next->ip_num; j++) {
				if (time > ptr2->next->ip_ttl[j]) {/*��¼���ڣ�ɾ��*/
					flag = 1;
					temp2 = ptr2->next->next;
					free(ptr2->next->cname);
					for (k = 0; k < ptr2->next->ip_num; k++) {
						free(ptr2->next->ip[k]);
					}
					free(ptr2->next->ip); free(ptr2->next->ip_ttl); free(ptr2->next);
					ptr2->next = temp2;
					break;
				}
			}
			if (flag == 0) {
				ptr2 = ptr2->next;
				count++;
			}	
		}
	}
	/*
	if (((double)count) / ip_hash > IP_MAX_OCCUPATION) {
		ip_hash *= 2;
		temp2 = (struct CNAME_IP_RECORD*)realloc(ip_record, sizeof(struct DOMAIN_CNAME_RECORD*) * ip_hash);
		if (temp2 != NULL) {
			ip_record = (struct CNAME_IP_RECORD**)temp2;
			printf("DEBUG:ip_hash increased! new hash: %d\n", ip_hash);
		}
		else {
			printf("DEBUG:realloc failed(ip) ,exit\n"); exit(1);
		}
	}
	if (((double)count) / ip_hash < IP_MIN_OCCUPATION && ip_hash >= 120) {
		ip_hash /= 2;
		temp2 = (struct CNAME_IP_RECORD*)realloc(ip_record, sizeof(struct DOMAIN_CNAME_RECORD*) * ip_hash);
		if (temp2 != NULL) {
			ip_record = (struct CNAME_IP_RECORD**)temp2;
			printf("DEBUG:ip_hash decreased! new hash: %d\n", ip_hash);
		}
		else {
			printf("DEBUG:realloc failed(ip) ,exit\n"); exit(1);
		}
	}*/
	if (Debug_Level >= 2) {
		printf("Time:%.3lf ", ((double)clock()) / 1000.0);
		printf("DEBUG:Ip record flushed! average cost:%lf  \n", ((double)count) / ip_hash);
	}
}
void addDomainIp(struct DNS dns) {
	for (int i = 0; i < dns.question_num; i++) {//���
		if (dns.que[i].class != 1 || dns.que[i].type != 1) {//��֤Ҫ��ӵ����ݶ���v4,ip��ѯ��Ӧ���
			return;
		}
	}
	addCnameIp(dns);
	addDomainCname(dns);
}

