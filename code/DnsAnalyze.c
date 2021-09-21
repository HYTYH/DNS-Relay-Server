#include<stdio.h>
#include<string.h>
#include<stdlib.h>
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
struct COMPRESS_INFO {
	unsigned char* name;
	unsigned short offset;
	short next;
};
static void myMemcpy(unsigned char* dst, unsigned char* src, unsigned int len) {/*ʵ�ִ�С�˲�ͬ�������ڴ���������ݿ���������src�ֽ�Ϊ01 02 03������Ϊ3������03 02 01��˳��д��dst*/
	unsigned int i;/*������*/
	for (i = 0; i < len; i++) {
		dst[i] = src[len - 1 - i];/*��src���ֽڷ�����������dst��*/
	}
}
static unsigned char* domainAnalyze(unsigned char* buff, unsigned char* dns) {/*�������ڽ���buff��ַ�ϵ���������00��0c��תָ���β��dnsΪ���ĵĳ�ʼ��ַ�����ڴ���0c��ת�����������*/
	int j, count;/*jΪ��������countΪ�������������ȣ�����'.'��*/
	unsigned char temp[1600];//�������������
	unsigned char* ret;//��������ռ䣬�����淵��

	for (count = 0; buff[0] != 0;) {/*buffָ�����ڱ�����ֱ��������0����*/
		if (buff[0] >= 0xc0) {/*��⵽��תָ��*/
			//printf("%.8x %.8x  %d  %d %d\n", buff, dns , ( long)((buff[0] & 0x3f) * 0x0100 + buff[1]),buff[0],buff[1]);
			buff = dns + (long long)((buff[0] & 0x3f) * 0x0100 + buff[1]);/*���ƫ������buff���µ���ת��ĵط�*/

		}
		else {/*������ת*/
			for (j = 0; j < buff[0]; j++) {/*��ʱ��ʽ��buffָ���ֽ���һ�������������������ֽڵĸ���*/
				temp[count + j] = buff[j + 1];/*һ���ֽ�һ���ֽڿ������˴�����memcpy*/
			}
			temp[count + j] = '.';/*�����󣬼���һ��'.'*/
			count += buff[0] + 1;/*���������£�������Ϊ�����ֽ����Լ�һ������ռ�ֽڣ�1��*/
			buff += buff[0] + 1;/*buffָ����µ���һ����ַ��������һ��������c0��תָ��*/
		}
	}
	if (count <= 0) {/*debug�ã������������������������²����п���������countΪ���������*/
		printf("count==0! wrong.\n");
		return NULL;
	}
	ret = (unsigned char*)malloc(sizeof(char) * (count));
	memcpy(ret, temp, count);
	ret[count - 1] = '\0';
	/*�����ڴ棬���������ڴ濽���������ڴ��ַ�ϣ���ĩβ��'.'�滻Ϊ\0�������ַ�����ĩβ*/
	return ret;
}
static unsigned int domainInverseAnalyze(unsigned char* dst, unsigned char* src) {/*��src����������ַ���ת��Ϊdns�����еĸ�ʽ,д��dst����www.baidu.com\0ת��Ϊ\03www\05baidu\03com������ת������Ч����*/
	int i, j, len;//i��jΪ����������lenΪ����ַ�������

	len = strlen(src);
	if (len <= 1) {/*����������մ�*/
		dst[0] = 0;
		return 1;
	}
	else {
		memcpy(dst + 1, src, (long long)len + 1);
		for (i = 0, j = 1; dst[j] != '\0'; j++) {/*����'.'��λ����д���ַ�������ע��src�ĵ�һ���ֽڲ���'.'���������λ��Ҫд����������д��dstǰʱ��������ƶ�һ���ֽڣ��൱����Ϊ����һ��'.'*/
			if (dst[j] == '.') {
				dst[i] = j - i - 1;
				i = j;
			}
		}
		dst[i] = j - i - 1;/*���һ�κ���û��'.',�������*/
		return j + 1;/*��ͬlen+2(������һ����ĩβ0һ������ǰ�����)*/
	}
}
unsigned int dataToDns(unsigned char* buff, struct DNS* dns) {//�������ڰ�buffָ����ָ���ԭʼdns����ת��Ϊ�������п�ʶ��ĸ�ʽ��������׶�ȡ�������������ֵĽ�ѹ����c0��תָ�������ԭʼdns���ĳ���
	unsigned int i, offset, domainlen;/*iΪ��������offset����ǰ����λ�õ�ƫ������domainlen��ʾ��ǰ��������������ڱ����еĳ��ȣ�������ת��*/
	/*��ʼ����ͷ�ֶ�*/
	myMemcpy((unsigned char*)&(dns->id), (void*)buff, 2);/*����id�ֶΣ�����ʹ��myMemcpy����Ϊ��С�˸�ʽ������*/
	myMemcpy((unsigned char*)&(dns->question_num), buff + 4, 2);/*�����ĸ������ֶ�*/
	myMemcpy((unsigned char*)&(dns->answer_num), buff + 6, 2);
	myMemcpy((unsigned char*)&(dns->authority_num), buff + 8, 2);
	myMemcpy((unsigned char*)&(dns->additional_num), buff + 10, 2);
	dns->flag.qr = (buff[2] & 0x80) >> 7;/*����flag�ֶΣ�һ��8����ʶ*/
	dns->flag.opcode = (buff[2] & 0x78) >> 3;
	dns->flag.aa = (buff[2] & 0x04) >> 2;
	dns->flag.tc = (buff[2] & 0x02) >> 1;
	dns->flag.rd = (buff[2] & 0x01);
	dns->flag.ra = (buff[3] & 0x80) >> 7;
	dns->flag.z = 0;/*Ԥ���ֶΣ�����ʡ��*/
	dns->flag.rcode = (buff[3] & 0x0f);
	/*ͷ�ֶο������*/
	/*��ʼ�������⡢�ش��ֶ�*/
	/*��������ռ�*/
	if (dns->question_num > 0) {
		dns->que = (struct QUE*)malloc(sizeof(struct QUE) * dns->question_num);
	}
	else {
		dns->que = NULL;
	}/*question�ֶβ�Ϊ�գ�����ռ䣬����ֵ��ָ��*/
	if (dns->answer_num > 0) {
		dns->ans = (struct RR*)malloc(sizeof(struct RR) * dns->answer_num);
	}
	else {
		dns->ans = NULL;
	}/*answer�ֶβ�Ϊ�գ�����ռ䣬����ֵ��ָ��*/
	if (dns->authority_num > 0) {
		dns->aut = (struct RR*)malloc(sizeof(struct RR) * dns->authority_num);
	}
	else {
		dns->aut = NULL;
	}/*authority�ֶβ�Ϊ�գ�����ռ䣬����ֵ��ָ��*/
	if (dns->additional_num > 0) {
		dns->add = (struct RR*)malloc(sizeof(struct RR) * dns->additional_num);
	}
	else {
		dns->add = NULL;
	}/*addtional�ֶβ�Ϊ�գ�����ռ䣬����ֵ��ָ��*/
	/*4���ֶ�����ռ����*/
	/*��ʼ���ζ�ÿ���ռ丳ֵ*/
	for (i = 0, offset = 12; i < dns->question_num; i++) {
		/*������ȡ����*/
		if ((buff[offset] & 0xc0) != 0xc0) {/*������תָ��*/
			domainlen = strlen(buff + offset);/*����domain����*/
			dns->que[i].domain = domainAnalyze(buff + offset, buff);/*����domain�ֶΣ���ֵ��������ַ���*/
			offset += domainlen + 1;/*offset���£�����domain�ֶΣ�����+1����Ϊstrlenû��\0*/
			myMemcpy((unsigned char*)&(dns->que[i].type), buff + offset, 2);/*�ֱ𿽱�type��class�ֶ�*/
			myMemcpy((unsigned char*)&(dns->que[i].class), buff + offset + 2, 2);
			offset += 4;/*ƫ�������£�����class��type�ֶ�*/
		}
		else {/*����תָ��*/
			dns->que[i].domain = domainAnalyze(buff + offset, buff);/*ͬ�ϣ�����domain�ֶΣ�ƫ����ֻ��2���ֽ�*/
			offset += 2;
			myMemcpy((unsigned char*)&(dns->que[i].type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->que[i].class), buff + offset + 2, 2);
			offset += 4;
		}
	}
	/*question������ȡ���*/
	for (i = 0; i < dns->answer_num; i++) {
		/*������ȡ����*/
		/*��query����Ĵ���ע������*/
		if ((buff[offset] & 0xc0) != 0xc0) {/*������תָ��*/
			domainlen = strlen(buff + offset);
			dns->ans[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += domainlen + 1;
			myMemcpy((unsigned char*)&(dns->ans[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->ans[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		else {/*����תָ��*/
			dns->ans[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += 2;
			myMemcpy((unsigned char*)&(dns->ans[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->ans[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		/*������class��type��ȡ���*/
		/*��ʼ����RRS�ֶ�*/
		myMemcpy((unsigned char*)&(dns->ans[i].ttl), buff + offset, 4);/*����ttl��len�ֶ�*/
		myMemcpy((unsigned char*)&(dns->ans[i].len), buff + offset + 4, 2);
		/*ttl,len�������*/
		dns->ans[i].resource = (unsigned char*)malloc(sizeof(char) * (dns->ans[i].len));/*����len�ֶ�����ռ�*/
		memcpy((dns->ans[i].resource), buff + offset + 6, dns->ans[i].len);/*��resource�ֶο�����ע�����ﲻ��������Ϊ���ﲻ���������������������IP��ַ�ȵȣ��Դ�����Ĵ������ϲ�ģ��*/
		offset += 6 + dns->ans[i].len;/*offset���£�����ttl��len����Դ����*/
		if (dns->ans[i].que.class == 1 && dns->ans[i].que.type == 5) {/*������cname���Ͱ���Դ���ֽ���*/
			dns->ans[i].resource_string = domainAnalyze(dns->ans[i].resource, buff);
		}
		else {
			dns->ans[i].resource_string = NULL;
		}
	}
	/*�����Ϸ�����ȡʣ����������ע������*/
	for (i = 0; i < dns->authority_num; i++) {
		/*������ȡ����*/
		if ((buff[offset] & 0xc0) != 0xc0) {/*������תָ��*/
			domainlen = strlen(buff + offset);

			dns->aut[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += domainlen + 1;
			myMemcpy((unsigned char*)&(dns->aut[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->aut[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		else {/*����תָ��*/
			dns->aut[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += 2;
			myMemcpy((unsigned char*)&(dns->aut[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->aut[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		/*������class��type��ȡ���*/
		myMemcpy((unsigned char*)&(dns->aut[i].ttl), buff + offset, 4);
		myMemcpy((unsigned char*)&(dns->aut[i].len), buff + offset + 4, 2);
		/*ttl,len�������*/
		dns->aut[i].resource = (unsigned char*)malloc(sizeof(char) * (dns->aut[i].len));
		memcpy((dns->aut[i].resource), buff + offset + 6, dns->aut[i].len);
		offset += 6 + dns->aut[i].len;
		if (dns->aut[i].que.class == 1 && dns->aut[i].que.type == 5) {
			dns->aut[i].resource_string = domainAnalyze(dns->aut[i].resource, buff);
		}
		else {
			dns->aut[i].resource_string = NULL;
		}
	}
	for (i = 0; i < dns->additional_num; i++) {
		/*������ȡ����*/
		if ((buff[offset] & 0xc0) != 0xc0) {/*������תָ��*/
			domainlen = strlen(buff + offset);
			dns->add[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += domainlen + 1;
			myMemcpy((unsigned char*)&(dns->add[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->add[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		else {/*����תָ��*/
			dns->add[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += 2;
			myMemcpy((unsigned char*)&(dns->add[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->add[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		/*������class��type��ȡ���*/
		myMemcpy((unsigned char*)&(dns->add[i].ttl), buff + offset, 4);
		myMemcpy((unsigned char*)&(dns->add[i].len), buff + offset + 4, 2);
		/*ttl,len�������*/
		dns->add[i].resource = (unsigned char*)malloc(sizeof(char) * (dns->add[i].len));
		memcpy((dns->add[i].resource), buff + offset + 6, dns->add[i].len);
		offset += 6 + dns->add[i].len;
		if (dns->add[i].que.class == 1 && dns->add[i].que.type == 5) {
			dns->add[i].resource_string = domainAnalyze(dns->add[i].resource, buff);
		}
		else {
			dns->add[i].resource_string = NULL;
		}
	}
	/*ȫ����ȡ���*/
	return offset;
}
unsigned char* dnsToData(struct DNS* dns, unsigned int* len) {
	int i, j, offset, domainlen, infonum;/*i��jΪ��������offsetΪ�����ڴ�ʱ���ñ�������domianlenΪdomain���򳤶ȣ�infonumΪinfo����ı�����*/
	unsigned char temp[2048];
	unsigned char* ret;
	struct COMPRESS_INFO info[200];/*���ڱ��ĵ�ѹ�����Ա�����domain�����Լ�cname�������ظ����ַ�������c0��ת��ʾ���ṹ����offset��nextΪ-1ʱ������Ч��nextΪ-1�����Ӧ�ַ�����һ�γ��֣�next��Ϊ-1ʱ��ֵΪ��¼���ַ�����һ�γ��ֵĽṹ����±�*/
	memset(temp, 0, sizeof(temp));/*��������*/
	for (i = 0, infonum = 0; i < dns->question_num; i++) {
		if (dns->que[i].class == 1 && dns->que[i].type == 1) {/*��ʼ�����������ipv4��ip��ַ��ѯ*/
			info[infonum].name = dns->que[i].domain;
			info[infonum].next = -1;
			info[infonum].offset = 0;
			infonum++;
		}
	}
	for (i = 0; i < dns->answer_num; i++) {
		/*��ʼ�����������ipv4��ip��ַӦ���cnameӦ��*/
		if (dns->ans[i].que.class == 1 && dns->ans[i].que.type == 1) {
			info[infonum].name = dns->ans[i].que.domain;
			info[infonum].next = -1;
			info[infonum].offset = 0;
			infonum++;
		}
		else if (dns->ans[i].que.class == 1 && dns->ans[i].que.type == 5) {
			info[infonum].name = dns->ans[i].que.domain;
			info[infonum].next = -1;
			info[infonum].offset = 0;
			infonum++;
			info[infonum].name = dns->ans[i].resource_string;
			info[infonum].next = -1;
			info[infonum].offset = 0;
			infonum++;
		}
	}

	for (i = 0; i < infonum; i++) {/*����������Ч��Ϣ����������ѡ������ķ���������ÿ���ַ����Ƿ���������ƥ�䣬ƥ��֮���־λ��next���Ͳ�Ϊ-1�ˣ���������ʱ��ֱ������������ʱ�䣬�����д���ͬ�������ʱ�临�Ӷ�O(n),���д���ͬ�����O(n^2)*/
		if (info[i].next != -1) {
			continue;
		}
		for (j = i + 1; j < infonum; j++) {
			if (info[j].next != -1) {
				continue;
			}
			else {
				if (strcmp(info[i].name, info[j].name) == 0) {
					info[j].next = i;
				}
			}
		}
	}


	/*���ȿ���ͷ�ֶ�*/
	/*�ȿ���ͷ��id���ĸ������ֶ�*/

	myMemcpy(temp, (unsigned char*)(&dns->id), 2);
	myMemcpy(temp + 4, (unsigned char*)(&dns->question_num), 2);
	myMemcpy(temp + 6, (unsigned char*)(&dns->answer_num), 2);
	myMemcpy(temp + 8, (unsigned char*)(&dns->authority_num), 2);
	myMemcpy(temp + 10, (unsigned char*)(&dns->additional_num), 2);
	/*z֮�󿽱�flag�ֶ�*/
	temp[2] = 0; temp[3] = 0;//��ȫ��ֵ0
	temp[2] |= (dns->flag.qr << 7);
	temp[2] |= (dns->flag.opcode << 3);
	temp[2] |= (dns->flag.aa << 2);
	temp[2] |= (dns->flag.tc << 1);
	temp[2] |= (dns->flag.rd);
	temp[3] |= (dns->flag.ra << 7);
	temp[3] |= (dns->flag.rcode);
	/*flag�ֶο������*/

	for (i = 0, infonum = 0, offset = 12; i < dns->question_num; i++) {
		/*����query*/
		if (dns->que[i].class == 1 && dns->que[i].type == 1) {
			info[infonum].offset = offset;/*�Ե�һ����������ֻ��¼ƫ������������ѹ��*/
			infonum++;
		}
		domainlen = domainInverseAnalyze(temp + offset, dns->que[i].domain);
		offset += domainlen;
		myMemcpy(temp + offset, (unsigned char*)&(dns->que[i].type), 2);
		myMemcpy(temp + offset + 2, (unsigned char*)&(dns->que[i].class), 2);
		offset += 4;
	}
	for (i = 0; i < dns->answer_num; i++) {
		/*����query*/
		/*��Ӧ�����򣬲����¼����Ӧƫ�ƣ�ҲҪѹ��*/
		if (info[infonum].next == -1) {/*��Ӧ�ַ�����һ�γ���*/
			info[infonum].offset = offset;
			domainlen = domainInverseAnalyze(temp + offset, dns->ans[i].que.domain);
			offset += domainlen;
			infonum++;
		}
		else {/*���ǵ�һ�γ��֣���ô��c0��ת��ƫ����Ϊ��ǰinfo[infonum]��next����¼��offset,����ע���С�ˣ�������myMemcpy*/
			myMemcpy(temp + offset, (unsigned char*)&(info[info[infonum].next].offset), 2);
			temp[offset] |= 0xc0;/*�൱��ǰ��д��c0*/
			offset += 2;
			infonum++;
		}
		myMemcpy(temp + offset, (unsigned char*)&(dns->ans[i].que.type), 2);
		myMemcpy(temp + offset + 2, (unsigned char*)&(dns->ans[i].que.class), 2);
		offset += 4;
		/*����RRS*/
		myMemcpy(temp + offset, (unsigned char*)&(dns->ans[i].ttl), 4);/*����ttl*/
		if (dns->ans[i].que.type == 5 && dns->ans[i].que.class == 1) {/*�����cnameӦ��*/
			if (info[infonum].next == -1) {/*����ת*/
				info[infonum].offset = offset + 6;/*��¼ƫ��*/
				dns->ans[i].len = strlen(dns->ans[i].resource_string) + 2;/*д�볤��*/
				myMemcpy(temp + offset + 4, (unsigned char*)&(dns->ans[i].len), 2);/*���Ȳ���д�뻺��*/
				dns->ans[i].resource = (unsigned char*)malloc(sizeof(char) * dns->ans[i].len);/*����һ���ռ���ʱ��*/
				domainInverseAnalyze(dns->ans[i].resource, dns->ans[i].resource_string);/*��string��Ӧ������ת����ȥ*/
				memcpy(temp + offset + 6, (dns->ans[i].resource), dns->ans[i].len);/*��ת������д������*/
				free(dns->ans[i].resource);/*�ͷ��ⲿ����ʱ�õĿռ�*/
				infonum++;
			}
			else {
				dns->ans[i].len = 2;/*��ת���򳤶�Ϊ2*/
				myMemcpy(temp + offset + 4, (unsigned char*)&(dns->ans[i].len), 2);/*д�볤�Ⱥ�ƫ��*/
				myMemcpy(temp + offset + 6, (unsigned char*)&(info[info[infonum].next].offset), 2);
				temp[offset + 6] |= 0xc0;/*����ͷ����c0*/
				infonum++;
			}
		}
		else {/*����cname�ͣ�ֱ�ӿ�����Ӧ�ֽ�*/
			myMemcpy(temp + offset + 4, (unsigned char*)&(dns->ans[i].len), 2);
			memcpy(temp + offset + 6, (dns->ans[i].resource), dns->ans[i].len);
		}
		offset += dns->ans[i].len + 6;
	}
	/*����Ĳ����߼�ͬ��*/
	for (i = 0; i < dns->authority_num; i++) {
		/*����query*/
		domainlen = domainInverseAnalyze(temp + offset, dns->aut[i].que.domain);
		offset += domainlen;
		myMemcpy(temp + offset, (unsigned char*)&(dns->aut[i].que.type), 2);
		myMemcpy(temp + offset + 2, (unsigned char*)&(dns->aut[i].que.class), 2);
		offset += 4;
		/*����RRS*/
		myMemcpy(temp + offset, (unsigned char*)&(dns->aut[i].ttl), 4);
		if (dns->aut[i].que.type == 5 && dns->aut[i].que.class == 1) {
			dns->aut[i].len = strlen(dns->aut[i].resource_string) + 2;
			myMemcpy(temp + offset + 4, (unsigned char*)&(dns->aut[i].len), 2);
			dns->aut[i].resource = (unsigned char*)malloc(sizeof(char) * dns->aut[i].len);
			domainInverseAnalyze(dns->aut[i].resource, dns->aut[i].resource_string);
			memcpy(temp + offset + 6, (dns->aut[i].resource), dns->aut[i].len);
			free(dns->aut[i].resource);
		}
		else {
			myMemcpy(temp + offset + 4, (unsigned char*)&(dns->aut[i].len), 2);
			memcpy(temp + offset + 6, (dns->aut[i].resource), dns->aut[i].len);
		}
		offset += dns->aut[i].len + 6;
	}
	for (i = 0; i < dns->additional_num; i++) {
		/*����query*/
		domainlen = domainInverseAnalyze(temp + offset, dns->add[i].que.domain);
		offset += domainlen;
		myMemcpy(temp + offset, (unsigned char*)&(dns->add[i].que.type), 2);
		myMemcpy(temp + offset + 2, (unsigned char*)&(dns->add[i].que.class), 2);
		offset += 4;
		/*����RRS*/
		myMemcpy(temp + offset, (unsigned char*)&(dns->add[i].ttl), 4);
		if (dns->add[i].que.type == 5 && dns->add[i].que.class == 1) {
			dns->add[i].len = strlen(dns->add[i].resource_string) + 2;
			myMemcpy(temp + offset + 4, (unsigned char*)&(dns->add[i].len), 2);
			dns->add[i].resource = (unsigned char*)malloc(sizeof(char) * dns->add[i].len);
			domainInverseAnalyze(dns->add[i].resource, dns->add[i].resource_string);
			memcpy(temp + offset + 6, (dns->add[i].resource), dns->add[i].len);
			free(dns->add[i].resource);
		}
		else {
			myMemcpy(temp + offset + 4, (unsigned char*)&(dns->add[i].len), 2);
			memcpy(temp + offset + 6, (dns->add[i].resource), dns->add[i].len);
		}
		offset += dns->add[i].len + 6;
	}
	/*ת�����*/
	*len = offset;/*����offset������Ч����*/
	ret = (unsigned char*)malloc(sizeof(char) * offset);/*����ռ䣬���ڷ���*/
	memcpy(ret, temp, offset);/*�����ڴ�*/
	return ret;
}
void freeDns(struct DNS* dnsptr) {
	/*����ʵ�ֶ�dnsptrָ���DNS���ݿ��������������ͷ�ռ�õ��ڴ棬��������DNS���ݿ�����*/
	int i;/*�����ͷŶ�������*/
	for (i = 0; i < dnsptr->question_num; i++) {
		free(dnsptr->que[i].domain);/*���ⲿ���ͷ�*/
	}
	dnsptr->que = NULL;
	for (i = 0; i < dnsptr->answer_num; i++) {
		free(dnsptr->ans[i].que.domain);/*�ش�����ⲿ���ͷ�*/
		if (dnsptr->ans[i].que.type == 5 && dnsptr->ans[i].que.class == 1) {/*�����cname��resource��Ч��string��Ч���ͷ�string�������ͷ�resource*/
			free(dnsptr->ans[i].resource_string);
		}
		else {
			free(dnsptr->ans[i].resource);
		}
	}
	dnsptr->ans = NULL;
	for (i = 0; i < dnsptr->authority_num; i++) {/*�ͷ��߼�ͬ��*/
		free(dnsptr->aut[i].que.domain);
		if (dnsptr->aut[i].que.type == 5 && dnsptr->aut[i].que.class == 1) {
			free(dnsptr->aut[i].resource_string);
		}
		else {
			free(dnsptr->aut[i].resource);
		}
	}
	dnsptr->aut = NULL;
	for (i = 0; i < dnsptr->additional_num; i++) {
		free(dnsptr->add[i].que.domain);
		if (dnsptr->add[i].que.type == 5 && dnsptr->add[i].que.class == 1) {
			free(dnsptr->add[i].resource_string);
		}
		else {
			free(dnsptr->add[i].resource);
		}
	}
	dnsptr->add = NULL;
	memset(dnsptr, 0, sizeof(struct DNS));/*�������������������㣨�������㣬ָ����NULL��*/
}