#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include<stdio.h>
#include<winsock2.h>
#include<time.h>
#pragma comment(lib,"ws2_32.lib")
#define PORT_TO_CLIENT 53//�˿ں� 
//#define PORT_TO_SERVER 8555//����˿ں�
int SIO_UDP_CONNRESET = (int)(IOC_IN | IOC_VENDOR | 12);/*���ڽ��socket���������bug��10054*/
/*���²���Ϊ����ģ������*/
extern int Debug_Level;
extern char Server_Ip[16];/*����*/
SOCKET sock;/*�ͷ����������Լ��Ϳͻ������ӵ�sock��*/
struct sockaddr me, server_addr;/*��Է��������ͻ���ʱ�Լ��ĵ�ַ���Լ��ⲿDNS�������ĵ�ַ*/
struct ID_IP_TRANS_INFO {
	struct ID_IP_TRANS_INFO* next;/*��ͬhash����һ����¼*/
	unsigned short id;/*�ӿͻ�������ʱ���id*/
	unsigned short trans_id;/*�ͷ�����ͨ��ʱʹ�õ�id*/
	struct sockaddr addr; /*�ͻ��˵ĵ�ַ*/
	int ttl;/*����ʱ��*/
}trans_info[256];
static void myMemcpy(unsigned char* dst, unsigned char* src, unsigned int len) {/*ʵ�ִ�С�˲�ͬ�������ڴ���������ݿ���������src�ֽ�Ϊ01 02 03������Ϊ3������03 02 01��˳��д��dst*/
	unsigned int i;/*������*/
	for (i = 0; i < len; i++) {
		dst[i] = src[len - 1 - i];/*��src���ֽڷ�����������dst��*/
	}
}
static void addTransInfo(unsigned short id, struct sockaddr addr, unsigned short trans_id) {/*��idת����¼����뻺�棬����idΪԭʼid��addrΪ�ͻ��˵�ַ��trans_idΪת����id*/
	unsigned short hash = (trans_id * 77) % 256;/*��¼λ��Ϊת����id*77%256*/
	struct ID_IP_TRANS_INFO* temp;
	/*ͷ���¼*/
	temp = (struct ID_IP_TRANS_INFO*)malloc(sizeof(struct ID_IP_TRANS_INFO));
	temp->next = trans_info[hash].next;
	temp->id = id;
	temp->trans_id = trans_id;
	temp->addr = addr;
	temp->ttl = clock() + 4000;/*4����Ч*/
	trans_info[hash].next = temp;
}
static int findTransInfo(unsigned short trans_id, struct sockaddr* addr, unsigned short* id) {/*����idѰ�Ҵ洢����Ч��¼��trans_idΪҪ���ҵ�id�����ҽ���пͻ��˵�ַд��addrָ���ڴ棬��Ӧԭʼidд��idָ���ڴ��У�������ҳɹ��򷵻�1��ʧ���򷵻�0*/
	if (Debug_Level >= 2) {
		printf("Time:%.3lf Start Finding id\n", (double)clock() / 1000);
	}
	unsigned short hash = (trans_id * 77) % 256;/*�����Ӧhash*/
	struct ID_IP_TRANS_INFO* temp;
	for (temp = trans_info[hash].next; temp != NULL; temp = temp->next) {/*��hash��Ӧλ�ÿ�ʼ��*/
		if (clock() < temp->ttl && trans_id == temp->trans_id) {/*ƥ�䣬û���ڣ����ҳɹ�*/
			*addr = temp->addr;
			*id = temp->id;
			return 1;
		}
	}
	return 0;/*����������Ҳû���أ������ʧ��*/
}
void transInfoFlush(void) {
	int time = clock();
	struct ID_IP_TRANS_INFO* temp1,*temp2;//temp2Ϊtemp1��ǰһ���ڵ㣬����ɾ������
	for (int i = 0; i < 256; i++) {
		for (temp1 = trans_info[i].next, temp2 = &trans_info[i]; temp1 != NULL; temp1 = temp1->next) {
			if (temp1->ttl < time) {//���ڼ�¼
				temp2->next = temp1->next;
				free(temp1);
				temp1 = temp2;
			}
			temp2 = temp1;
		}
	}
}
void transInfoInit(void) {
	srand(time(NULL));/*���²���*/
	for (int i = 0; i < 256; i++) {
		trans_info[i].next = NULL;/*ֻ��ͷ�ڵ�*/
	}
}
void networkConnectionInit(void) {
	BOOL bEnalbeConnRestError = FALSE;/*���ڽ��socket���������bug��10054*/
	DWORD dwBytesReturned = 0;/*���ڽ��socket���������bug��10054*/
	WORD sockVersion = MAKEWORD(2, 2);/*WSA��ʼ��*/
	WSADATA wsaData;
	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		printf("WSA Wrong!\n"); exit(1);
	}
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	WSAIoctl(sock, SIO_UDP_CONNRESET, &bEnalbeConnRestError, sizeof(bEnalbeConnRestError), \
		NULL, 0, &dwBytesReturned, NULL, NULL);/*���ڽ��socket���������bug��10054*/

	if (sock == -1) {
		printf("wrong!%d\n",WSAGetLastError()); exit(1);
	}
	struct sockaddr_in temp;
	memset(&temp, 0, sizeof(temp));
	temp.sin_family = AF_INET;  //���õ�ַ����
	temp.sin_port = htons(PORT_TO_CLIENT);  //���ö˿�
	temp.sin_addr.s_addr = inet_addr("0.0.0.0");  //���õ�ַ
	me = *((struct sockaddr*)(&temp));	
	if (bind(sock, &me, sizeof(struct sockaddr)) < 0) {
		printf("bind wrong!\n"); exit(2);
	}	
	temp.sin_family = AF_INET;  //���õ�ַ����
	temp.sin_port = htons(PORT_TO_CLIENT);  //���ö˿�
	temp.sin_addr.s_addr = inet_addr(Server_Ip);  //���õ�ַ
	server_addr = *((struct sockaddr*)(&temp));
}
void sendDns(unsigned char* buff, int len) {
	int sended;
	unsigned short id, id_trans;
	struct sockaddr dst;
	if ((buff[2] & 0x80) != 0) {/*Ӧ����*/
		myMemcpy(&id_trans, buff, 2);
		if (findTransInfo(id_trans, &dst, &id) == 0) {/*��Ӧת�������ǲ鲻��Ӧ��ת����ʲô*/
			if (Debug_Level >= 2) {
				printf("Time:%.3lf ", ((double)clock()) / 1000.0);
				printf("Id Trans Not found! %.4x -> ??\n", id_trans);
			}
		}
		else {/*�ɹ�ת�������������*/
			if (Debug_Level >= 2) {
				printf("Time:%.3lf ", ((double)clock()) / 1000.0);
				printf("FOUND succ!%.4x->%.4x\n", id_trans, id);
			}
			myMemcpy(buff, &id, 2);
			if ((sended = sendto(sock, buff, len, 0, &dst, sizeof(dst))) < len) {/*�ҵ���ת����id���Ƿ���ʧ��*/
				if (Debug_Level >= 2) {
					printf("Time:%.3lf ", ((double)clock()) / 1000.0);
					printf("send failed!(but found), len=%d,sended=%d\n", len, sended);
				}
			}
			else {/*���ͳɹ�*/
				if (Debug_Level >= 2) {
					printf("Time:%.3lf ", ((double)clock()) / 1000.0);
					printf("sendDns:send response succ! id:%.4x\n", id);
				}
			}
		}
	}
	else {//��ѯ����
		if ((sended = sendto(sock, buff, len, 0, &server_addr, sizeof(server_addr))) < len) {/*����ʧ��*/
			if (Debug_Level >= 2) {
				printf("Time:%.3lf ", ((double)clock()) / 1000.0);
				printf("send failed! len=%d,sended=%d\n", len, sended);
				printf("WSA Wrong %d\n", WSAGetLastError());
			}
		}
		else {/*���ͳɹ�*/
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
		if ((buff[2] & 0x80) != 0) {//Ӧ��
			myMemcpy(&id, buff, 2);
			if (Debug_Level >= 2) {
				printf("Time:%.3lf ", ((double)clock()) / 1000.0);
				printf("recieve id: %.4x\n", id);
			}
			return ret;
		}
		//��ѯ��
		while (1) {
			hash = ((rand() % 65535) * 77777) % 65536;/*���һ��0-65535�ڵ�������Ϊת����id*/
			if (findTransInfo(hash, &temp2, &id) == 0) {/*û�б�ռ�ã�Ҳ������ת�����id����*/
				myMemcpy(&id, buff, 2);
				addTransInfo(id, temp, hash);/*���ת��*/
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

