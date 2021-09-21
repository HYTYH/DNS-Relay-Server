#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include<time.h>
#include<string.h>
#include<pthread.h>
#include "Transmission.h"
#include "Debug.h"
#include "DnsAnalyze.h"
#include "QuerySystem.h"

#define DOMAIN_IP_RECORD_FLUSH_TIME 2000/*domain-ip记录查询模块刷新周期*/
#define ID_IP_TRANSTABLE_FLUSH_TIME 3000/*id转换模块刷新周期*/

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
/*以下为多模块所用全局变量*/
int Debug_Level = 1;
char Server_Ip[16] = "8.8.8.8";
char Set_File[64] = "sets.txt";
int Argv_Info[3] = { 0,0,0 };//判断是否有对应命令行参数，第一个数代表是否指明调试等级，第二个代表是否指明文件路径，第三个代表是否指定dns服务器地址
/*下面为线程锁以及线程函数*/
CRITICAL_SECTION mutex;/*线程锁（使用互斥量）*/
DWORD WINAPI recieveProcessDns(void);//接收处理进程
DWORD WINAPI localRecordFlush(void);/*刷新进程（定期执行刷新函数）*/
/*下面为参数处理函数*/
void argvProcess(int argc, char* argv[]);
/*下面为main函数*/
int main(int argc, char* argv[]) {
	argvProcess(argc, argv);
	recordInit();/*domain-ip记录查询模块初始化*/
	networkConnectionInit();/*网络连接模块初始化*/
	transInfoInit();/*id转化模块初始化*/
	InitializeCriticalSection(&mutex);/*线程锁初始化*/

    HANDLE handle1 = CreateThread(NULL, 0, recieveProcessDns, NULL, 0, NULL);/*外部服务器接收进程*/
	HANDLE handle2 = CreateThread(NULL, 0, localRecordFlush, NULL, 0, NULL);/*刷新进程*/
	while (1) {
		Sleep(8000000);/*main函数挂起*/
	}
	return 0;
}

DWORD WINAPI recieveProcessDns(void) {
	unsigned char buffer1[2560];
	unsigned char* bufferptr;
	int datalen, state;
	struct DNS dns1, dns2;
	while (1) {
		datalen = recieveDns(buffer1);
		if (datalen < 0) {
			continue;
		}
		dataToDns(buffer1, &dns1);
		debugDns(dns1);
		EnterCriticalSection(&mutex);/*加锁*/
		if (dns1.flag.qr == 1) {
			addDomainIp(dns1);
			sendDns(buffer1, datalen);
		}
		else {
			state = queryDomainIp(&dns2, dns1);
			if (state <= 0) {
				if (Debug_Level >= 1) {
					printf("Time:%.3lf ", ((double)clock()) / 1000.0);
					printf("Query Ip Failed ,relaying...\n");
				}
				sendDns(buffer1, datalen);
			}
			else {
				if (Debug_Level >= 1) {
					printf("Time:%.3lf ", ((double)clock()) / 1000.0);
					printf("Query Ip Succ! responsing...\n");
				}
				bufferptr = dnsToData(&dns2, &datalen);
				sendDns(bufferptr, datalen);
				free(bufferptr);
			}
			freeDns(&dns2);
		}
		freeDns(&dns1);
		LeaveCriticalSection(&mutex);/*解锁*/
	}
}
DWORD WINAPI localRecordFlush(void) {
	int time_count1 = 1, time_count2 = 1;

	while (1) {
		Sleep(100);
		if (clock() > time_count1 * DOMAIN_IP_RECORD_FLUSH_TIME) {
			EnterCriticalSection(&mutex);/*加锁*/
			time_count1++;
			domainIpRecordFlush();
			LeaveCriticalSection(&mutex);/*解锁*/
		}
		if (clock() > time_count2 * ID_IP_TRANSTABLE_FLUSH_TIME) {
			EnterCriticalSection(&mutex);/*加锁*/
			time_count2++;
			transInfoFlush();
			LeaveCriticalSection(&mutex);/*解锁*/
		}
	}
}
void argvProcess(int argc, char* argv[]) {
	int i;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {/*是调试等级*/
			Argv_Info[0] = 1;
			Debug_Level = strlen(argv[i]) - 1;
			if (Debug_Level >= 3 || Debug_Level < 0) {
				printf("Debug_Level error! %d,turn to level 2\n", Debug_Level);
				Debug_Level = 2;
			}
		}
		else if ((argv[i][0] <= 'Z' && argv[i][0] >= 'A') || (argv[i][0] <= 'z' && argv[i][0] >= 'a')) {/*是文件路径*/
			Argv_Info[2] = 1;
			strcpy(Set_File, argv[i]);
		}
		else if (argv[i][0] <= '9' && argv[i][0] >= '0') {/*是ip*/
			Argv_Info[1] = 1;
			strcpy(Server_Ip, argv[i]);
		}
		else {
			printf("Argv Wrong!\n");
		}
	}
	if (Argv_Info[0] == 0) {
		printf("Using Default Debug Level (1)\n");
	}
	if (Argv_Info[1] == 0) {
		printf("Using Default Server Ip Addr\n");
	}
	if (Argv_Info[2] == 0) {
		printf("Using Default SetFile name\n");
	}
}
