#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include<stdio.h>
#include<winsock2.h>
#include<time.h>
#pragma comment(lib,"ws2_32.lib")
#define PORT_TO_CLIENT 53//端口号 
//#define PORT_TO_SERVER 8555//对外端口号
int SIO_UDP_CONNRESET = (int)(IOC_IN | IOC_VENDOR | 12);/*用于解决socket函数本身的bug：10054*/
/*以下部分为接收模块所用*/
extern int Debug_Level;
extern char Server_Ip[16];/*引用*/
SOCKET sock;/*和服务器连接以及和客户端连接的sock号*/
struct sockaddr me, server_addr;/*面对服务器、客户端时自己的地址，以及外部DNS服务器的地址*/
struct ID_IP_TRANS_INFO {
	struct ID_IP_TRANS_INFO* next;/*相同hash的下一个记录*/
	unsigned short id;/*从客户端来的时候的id*/
	unsigned short trans_id;/*和服务器通信时使用的id*/
	struct sockaddr addr; /*客户端的地址*/
	int ttl;/*过期时间*/
}trans_info[256];
static void myMemcpy(unsigned char* dst, unsigned char* src, unsigned int len) {/*实现大小端不同的两块内存区域的数据拷贝，比如src字节为01 02 03，长度为3，则以03 02 01的顺序写入dst*/
	unsigned int i;/*遍历量*/
	for (i = 0; i < len; i++) {
		dst[i] = src[len - 1 - i];/*把src的字节反过来拷贝入dst中*/
	}
}
static void addTransInfo(unsigned short id, struct sockaddr addr, unsigned short trans_id) {/*将id转换记录添加入缓存，其中id为原始id，addr为客户端地址，trans_id为转换后id*/
	unsigned short hash = (trans_id * 77) % 256;/*记录位置为转换后id*77%256*/
	struct ID_IP_TRANS_INFO* temp;
	/*头插记录*/
	temp = (struct ID_IP_TRANS_INFO*)malloc(sizeof(struct ID_IP_TRANS_INFO));
	temp->next = trans_info[hash].next;
	temp->id = id;
	temp->trans_id = trans_id;
	temp->addr = addr;
	temp->ttl = clock() + 4000;/*4秒有效*/
	trans_info[hash].next = temp;
}
static int findTransInfo(unsigned short trans_id, struct sockaddr* addr, unsigned short* id) {/*根据id寻找存储的有效记录，trans_id为要查找的id，查找结果中客户端地址写入addr指向内存，对应原始id写入id指向内存中，如果查找成功则返回1，失败则返回0*/
	if (Debug_Level >= 2) {
		printf("Time:%.3lf Start Finding id\n", (double)clock() / 1000);
	}
	unsigned short hash = (trans_id * 77) % 256;/*计算对应hash*/
	struct ID_IP_TRANS_INFO* temp;
	for (temp = trans_info[hash].next; temp != NULL; temp = temp->next) {/*从hash对应位置开始找*/
		if (clock() < temp->ttl && trans_id == temp->trans_id) {/*匹配，没过期，查找成功*/
			*addr = temp->addr;
			*id = temp->id;
			return 1;
		}
	}
	return 0;/*遍历结束了也没返回，则查找失败*/
}
void transInfoFlush(void) {
	int time = clock();
	struct ID_IP_TRANS_INFO* temp1,*temp2;//temp2为temp1的前一个节点，便于删除操作
	for (int i = 0; i < 256; i++) {
		for (temp1 = trans_info[i].next, temp2 = &trans_info[i]; temp1 != NULL; temp1 = temp1->next) {
			if (temp1->ttl < time) {//过期记录
				temp2->next = temp1->next;
				free(temp1);
				temp1 = temp2;
			}
			temp2 = temp1;
		}
	}
}
void transInfoInit(void) {
	srand(time(NULL));/*重新播种*/
	for (int i = 0; i < 256; i++) {
		trans_info[i].next = NULL;/*只有头节点*/
	}
}
void networkConnectionInit(void) {
	BOOL bEnalbeConnRestError = FALSE;/*用于解决socket函数本身的bug：10054*/
	DWORD dwBytesReturned = 0;/*用于解决socket函数本身的bug：10054*/
	WORD sockVersion = MAKEWORD(2, 2);/*WSA初始化*/
	WSADATA wsaData;
	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		printf("WSA Wrong!\n"); exit(1);
	}
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	WSAIoctl(sock, SIO_UDP_CONNRESET, &bEnalbeConnRestError, sizeof(bEnalbeConnRestError), \
		NULL, 0, &dwBytesReturned, NULL, NULL);/*用于解决socket函数本身的bug：10054*/

	if (sock == -1) {
		printf("wrong!%d\n",WSAGetLastError()); exit(1);
	}
	struct sockaddr_in temp;
	memset(&temp, 0, sizeof(temp));
	temp.sin_family = AF_INET;  //设置地址家族
	temp.sin_port = htons(PORT_TO_CLIENT);  //设置端口
	temp.sin_addr.s_addr = inet_addr("0.0.0.0");  //设置地址
	me = *((struct sockaddr*)(&temp));	
	if (bind(sock, &me, sizeof(struct sockaddr)) < 0) {
		printf("bind wrong!\n"); exit(2);
	}	
	temp.sin_family = AF_INET;  //设置地址家族
	temp.sin_port = htons(PORT_TO_CLIENT);  //设置端口
	temp.sin_addr.s_addr = inet_addr(Server_Ip);  //设置地址
	server_addr = *((struct sockaddr*)(&temp));
}
void sendDns(unsigned char* buff, int len) {
	int sended;
	unsigned short id, id_trans;
	struct sockaddr dst;
	if ((buff[2] & 0x80) != 0) {/*应答报文*/
		myMemcpy(&id_trans, buff, 2);
		if (findTransInfo(id_trans, &dst, &id) == 0) {/*本应转换，但是查不到应该转换成什么*/
			if (Debug_Level >= 2) {
				printf("Time:%.3lf ", ((double)clock()) / 1000.0);
				printf("Id Trans Not found! %.4x -> ??\n", id_trans);
			}
		}
		else {/*成功转换（正常情况）*/
			if (Debug_Level >= 2) {
				printf("Time:%.3lf ", ((double)clock()) / 1000.0);
				printf("FOUND succ!%.4x->%.4x\n", id_trans, id);
			}
			myMemcpy(buff, &id, 2);
			if ((sended = sendto(sock, buff, len, 0, &dst, sizeof(dst))) < len) {/*找到了转换的id但是发送失败*/
				if (Debug_Level >= 2) {
					printf("Time:%.3lf ", ((double)clock()) / 1000.0);
					printf("send failed!(but found), len=%d,sended=%d\n", len, sended);
				}
			}
			else {/*发送成功*/
				if (Debug_Level >= 2) {
					printf("Time:%.3lf ", ((double)clock()) / 1000.0);
					printf("sendDns:send response succ! id:%.4x\n", id);
				}
			}
		}
	}
	else {//查询报文
		if ((sended = sendto(sock, buff, len, 0, &server_addr, sizeof(server_addr))) < len) {/*发送失败*/
			if (Debug_Level >= 2) {
				printf("Time:%.3lf ", ((double)clock()) / 1000.0);
				printf("send failed! len=%d,sended=%d\n", len, sended);
				printf("WSA Wrong %d\n", WSAGetLastError());
			}
		}
		else {/*发送成功*/
			myMemcpy(&id, buff, 2);
			if (Debug_Level >= 2) {
				printf("Time:%.3lf ", ((double)clock()) / 1000.0);
				printf("sendDns:send query succ! id:%.4x\n", id);
			}
		}
	}
}
int recieveDns(unsigned char* buff) {
	struct sockaddr temp,temp2;
	int addrlen;
	unsigned short id, hash;
	addrlen = sizeof(SOCKADDR);
	int ret = recvfrom(sock, buff, 2560, 0, &temp, &addrlen);
	if (ret == -1 || addrlen != sizeof(struct sockaddr)) {
		if (Debug_Level >= 2) {
			printf("Time:%.3lf ", ((double)clock()) / 1000.0);
			printf("recieve wrong!(client)%d\n", WSAGetLastError());
		}
		return ret;
	}
	else {
		if ((buff[2] & 0x80) != 0) {//应答
			myMemcpy(&id, buff, 2);
			if (Debug_Level >= 2) {
				printf("Time:%.3lf ", ((double)clock()) / 1000.0);
				printf("recieve id: %.4x\n", id);
			}
			return ret;
		}
		//查询包
		while (1) {
			hash = ((rand() % 65535) * 77777) % 65536;/*随机一个0-65535内的数，作为转换后id*/
			if (findTransInfo(hash, &temp2, &id) == 0) {/*没有被占用，也就是是转换后的id可用*/
				myMemcpy(&id, buff, 2);
				addTransInfo(id, temp, hash);/*添加转换*/
				myMemcpy(buff, &hash, 2);
				if (Debug_Level >= 2) {
					printf("Time:%.3lf ", ((double)clock()) / 1000.0);
					printf("add %.4x<->%.4x   \n", id, hash);
				}
				break;
			}
		}
		return ret;
	}
}
void DEBUG(void) {
	printf("SERVER IS RUNNING!\n\n");
}

