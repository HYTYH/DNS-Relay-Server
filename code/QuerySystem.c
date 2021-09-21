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
struct DNS presets;/*预设的DNS信息*/
static void addAnswer(struct DNS* dns, struct RR add) {/*将add处资源区域数据写入dns的ans区域中，包括更改资源区域数量以及内存申请*/
	
	/*修改空间大小*/
	struct RR* temp;
	temp = realloc(dns->ans, sizeof(struct RR) * (dns->answer_num + (long long)1));
	if (temp == NULL) {
		printf("realloc failed!\n");
		exit(1);
	}
	dns->ans = temp;
	/*逐个赋值*/
	dns->ans[dns->answer_num] = add;/*把ttl和len拷贝过来*/
	dns->ans[dns->answer_num].que.domain = (unsigned char*)malloc(sizeof(char) * (strlen(add.que.domain) + 1));
	strcpy(dns->ans[dns->answer_num].que.domain, add.que.domain);
	if (dns->ans[dns->answer_num].que.class == 1 && dns->ans[dns->answer_num].que.type == 5) {/*cname应答，string区域有效*/
		dns->ans[dns->answer_num].resource_string = (unsigned char*)malloc(sizeof(char) * (strlen(add.resource_string) + 1));
		strcpy(dns->ans[dns->answer_num].resource_string, add.resource_string);
		dns->ans[dns->answer_num].resource = NULL;
	}
	else if (dns->ans[dns->answer_num].que.class == 1 && dns->ans[dns->answer_num].que.type == 1) {/*ip应答，resource有效*/
		dns->ans[dns->answer_num].resource = (unsigned char*)malloc(sizeof(char) * (add.len));
		memcpy(dns->ans[dns->answer_num].resource, add.resource, add.len);
		dns->ans[dns->answer_num].resource_string = NULL;
	}
	else {
		printf("DEBUG:add not cname nor ipv4 ,wrong!\n"); exit(1);/*不是cname也不是ip*/
	}
	/*修改数字字段*/
	dns->answer_num += 1;
}
static int hashCalculate(unsigned char* src, int hashnum) {/*计算src处对应字符串在domain-ip转换过程中对应哈希值，用于定位记录的位置*/
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
static void freeIpRecord(struct CNAME_IP_RECORD* record, int mode) {/*清空CNAME-ip中一条记录，mode代表模式，如果为0代表完全释放，否则不释放cname部分*/
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
	if (mode == 0) {/*完全释放*/
		free(record->cname); record->cname = NULL;
	}
}
static void addCnameIp(struct DNS dns) {/*将dns报文中所有cname-ip的回答添加入转换的记录中*/
	int i, time, iplen, cnamelen, hash, flag;
	struct CNAME_IP_RECORD* current;
	unsigned char** temp;
	int* temp2;
	iplen = 4;
	time = clock();
	
	for (i = 0; i < dns.answer_num; i++) {
		if (dns.ans[i].que.type == 1 && dns.ans[i].que.class == 1) {/*是IPv4的Cname-IP应答*/
			cnamelen = strlen(dns.ans[i].que.domain);
			hash = hashCalculate(dns.ans[i].que.domain, ip_hash);
			for (current = ip_record[hash]->next, flag = 0; current != NULL; current = current->next) {
				if (strcmp(current->cname, dns.ans[i].que.domain) == 0) {/*存在匹配记录，则更新ip*/
					if (current->flag == 0) {
						freeIpRecord(current, 1);/*先把原来的释放了,mode=1，代表不清空domain区域*/
						current->flag = 1;
					}
					current->ip_num += 1;/*加一条记录*/
					temp = (unsigned char**)realloc(current->ip, sizeof(unsigned char*) * current->ip_num);/*分配空间*/
					if (temp != NULL) {/*分配成功*/
						current->ip = (unsigned char**)temp;
					}
					else {/*分配失败*/
						printf("error!"); exit(1);
					}
					current->ip[current->ip_num - 1] = (unsigned char*)malloc(sizeof(unsigned char) * iplen);/*最新一个ip分配4个字节空间*/
					temp2 = (int*)realloc(current->ip_ttl, sizeof(int) * current->ip_num);
					if (temp2 != NULL) {
						current->ip_ttl = (int*)temp2;
					}
					else {
						printf("error!"); exit(1);

					}
					current->ip_ttl[current->ip_num - 1] = time + 1000 * dns.ans[i].ttl;
					memcpy(current->ip[current->ip_num - 1], dns.ans[i].resource, iplen);
					flag = 1; break;/*查到了，跳出*/
				}
			}
			if (flag == 0) {/*没查到，头插*/
				current = (struct CNAME_IP_RECORD*)malloc(sizeof(struct CNAME_IP_RECORD));
				current->cname = (unsigned char*)malloc(sizeof(char) * (strlen(dns.ans[i].que.domain) + 1));
				strcpy(current->cname, dns.ans[i].que.domain);
				current->ip_num = 1;
				current->ip = (unsigned char**)malloc(sizeof(unsigned char*) * current->ip_num);
				current->ip[current->ip_num - 1] = (unsigned char*)malloc(sizeof(unsigned char) * iplen);
				current->ip_ttl = (int*)malloc(sizeof(int) * current->ip_num);
				current->ip_ttl[current->ip_num - 1] = time + 1000 * dns.ans[i].ttl;
				memcpy(current->ip[current->ip_num - 1], dns.ans[i].resource, iplen);
				current->flag = 1;/*代表是本次操作中添加的，如果再遇到，不清楚已存在的，只添加*/
				current->next = ip_record[hash]->next;
				ip_record[hash]->next = current;
			}
		}
	}
	for (i = 0; i < dns.answer_num; i++) {
		if (dns.ans[i].que.type == 1 && dns.ans[i].que.class == 1) {/*是IPv4的Cname-IP应答*/
			for (current = ip_record[hash]->next, flag = 0; current != NULL; current = current->next) {
				if (strcmp(current->cname, dns.ans[i].que.domain) == 0) {
					current->flag = 0; break;
				}
			}
		}
	}
}
static void addDomainCname(struct DNS dns) {/*将dns报文中所有domian-cname的回答添加入转换的记录中*/
	int i, time, domainlen, cnamelen, hash, flag;
	struct DOMAIN_CNAME_RECORD* current;
	time = clock();
	
	for (i = 0; i < dns.answer_num; i++) {
		if (dns.ans[i].que.type == 5 && dns.ans[i].que.class == 1) {/*是IPv4的Cname应答*/
			domainlen = strlen(dns.ans[i].que.domain);
			cnamelen = strlen(dns.ans[i].resource_string);
			hash = hashCalculate(dns.ans[i].que.domain, cname_hash);/*计算对应hash*/
			for (current = cname_record[hash]->next, flag = 0; current != NULL; current = current->next) {/*找到hash对应记录部分起点，开始遍历*/
				if (time < current->ttl && strcmp(current->domain, dns.ans[i].que.domain) == 0) {/*假如找到了还没有过期的相同记录*/
					if (strcmp(current->cname, dns.ans[i].resource_string) != 0) {/*资源记录部分不一样，需要更新*/
						free(current->cname);
						current->cname = (unsigned char*)malloc((sizeof(char)) * (cnamelen + 1));/*重新分配大小*/
						strcpy(current->cname, dns.ans[i].resource_string);/*把新的资源部分拷贝到记录上*/
					}
					current->ttl = time + 1000 * dns.ans[i].ttl;/*更新ttl*/
					flag = 1; break;/*更改flag表示，表示记录已存在并且已经更新完成，出循环*/
				}
			}
			if (flag == 0) {/*假如没找到，没更新，那么头插该记录*/
				current = (struct DOMAIN_CNAME_RECORD*)malloc(sizeof(struct DOMAIN_CNAME_RECORD));
				current->ttl = time + 1000 * dns.ans[i].ttl;/*计算ttl*/
				current->next = cname_record[hash]->next;/*next字段赋值*/
				current->domain = (unsigned char*)malloc(domainlen + 1);/*domain，cname字段分配空间，拷贝字符串*/
				current->cname = (unsigned char*)malloc(cnamelen + 1);
				strcpy(current->domain, dns.ans[i].que.domain);
				strcpy(current->cname, dns.ans[i].resource_string);
				cname_record[hash]->next = current;/*头指针指向新分配的空间的地址*/
			}
			/*处理完毕*/
		}
	}
}
static struct DOMAIN_CNAME_RECORD* queryCname(unsigned char* src) {/*查询src对应字符串的cname，查询成功则返回记录对应数据的地址，如果失败（无记录或过期）则返回NULL*/
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
static struct CNAME_IP_RECORD* queryIp(unsigned char* src) {/*查询src对应字符串的ip，查询成功则返回记录对应数据的地址，如果失败（无记录或过期）则返回NULL*/
	struct CNAME_IP_RECORD* current;
	int time, hash, i;
	time = clock();
	hash = hashCalculate(src, ip_hash);
	for (current = ip_record[hash]->next; current != NULL; current = current->next) {
		if (strcmp(current->cname, src) == 0) {
			for (i = 0; i < current->ip_num; i++) {
				if (current->ip_ttl[i] <= time) {/*有过期的*/
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
void recordInit(void) {/*domain-ip转换功能的初始化*/
	int i;
	/*依次分配空间后清零*/
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
	/*开始导入预设信息*/
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
	if (fd == NULL) {/*没找到预设文件*/
		if (Debug_Level >= 1) {
			printf("Not found FILE\n");
		}
	}
	else {
		if (Debug_Level >= 1) {
			printf("\"%s\" found!\n", Set_File);/*找到预设文件*/
		}
		while (scanf("%s %d.%d.%d.%d\n", buff, buff2, buff2 + 1, buff2 + 2, buff2 + 3) != EOF) {
			strcpy(temp.que.domain, buff);
			temp.resource[0] = buff2[0]; temp.resource[1] = buff2[1]; temp.resource[2] = buff2[2]; temp.resource[3] = buff2[3];
			addAnswer(&presets, temp);/*将预设文件中的cname-ip添加入缓存*/
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
	dst->flag.aa = 0;/*非授权*/
	dst->flag.ra = 1;/*可递归*/
	dst->flag.tc = 0;/*不截断*/
	dst->flag.qr = 1;/*响应包*/
	dst->que = (struct QUE*)malloc(sizeof(struct QUE) * dst->question_num);
	for (i = 0; i < dst->question_num; i++) {
		dst->que[i].domain = (unsigned char*)malloc(sizeof(char) * (strlen(src.que[i].domain) + 1));
		dst->que[i].class = src.que[i].class;
		dst->que[i].type = src.que[i].type;
		strcpy(dst->que[i].domain, src.que[i].domain);
	}
	time = clock();

	for (i = 0; i < src.question_num; i++) {
		if (src.que[i].type == 1 && src.que[i].class == 1) {/*ipv4的domain-ip查询*/
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
			/*cname查完了，查ip*/
			//printf("DEBUG:Cname query finished!\n");
			ip = queryIp(que);
			if (ip == NULL) {
				//printf("DEBUG:ip query failed! cname:%s \n", que);
				return 0;/*查询失败，所查Ip有过期的，此时向上级服务器查询*/
			}
			else {/*查到了，没过期*/
				//printf("DEBUG:ip query succ! cname:%s\n",que);
				temp.que.class = 1; temp.que.type = 1;
				temp.que.domain = (unsigned char*)malloc(sizeof(char) * (strlen(que) + 1));
				strcpy(temp.que.domain, que);
				temp.resource_string = NULL;
				temp.resource = (unsigned char*)malloc(sizeof(char) * 4);
				temp.len = 4;
				for (i = 0; i < ip->ip_num; i++) {/*依次将cname-ip结果加入dst*/
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
				if (time > ptr2->next->ip_ttl[j]) {/*记录过期，删除*/
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
	for (int i = 0; i < dns.question_num; i++) {//检查
		if (dns.que[i].class != 1 || dns.que[i].type != 1) {//保证要添加的内容都是v4,ip查询的应答包
			return;
		}
	}
	addCnameIp(dns);
	addDomainCname(dns);
}

