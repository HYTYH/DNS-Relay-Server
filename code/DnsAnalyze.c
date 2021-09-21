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
struct COMPRESS_INFO {
	unsigned char* name;
	unsigned short offset;
	short next;
};
static void myMemcpy(unsigned char* dst, unsigned char* src, unsigned int len) {/*实现大小端不同的两块内存区域的数据拷贝，比如src字节为01 02 03，长度为3，则以03 02 01的顺序写入dst*/
	unsigned int i;/*遍历量*/
	for (i = 0; i < len; i++) {
		dst[i] = src[len - 1 - i];/*把src的字节反过来拷贝入dst中*/
	}
}
static unsigned char* domainAnalyze(unsigned char* buff, unsigned char* dns) {/*函数用于解析buff地址上的域名，以00或0c跳转指令结尾，dns为报文的初始地址，用于处理0c跳转后的域名解析*/
	int j, count;/*j为遍历量，count为解析后域名长度（包括'.'）*/
	unsigned char temp[1600];//缓存解析的数据
	unsigned char* ret;//用于申请空间，将缓存返回

	for (count = 0; buff[0] != 0;) {/*buff指针用于遍历，直到遍历到0结束*/
		if (buff[0] >= 0xc0) {/*检测到跳转指令*/
			//printf("%.8x %.8x  %d  %d %d\n", buff, dns , ( long)((buff[0] & 0x3f) * 0x0100 + buff[1]),buff[0],buff[1]);
			buff = dns + (long long)((buff[0] & 0x3f) * 0x0100 + buff[1]);/*提出偏移量，buff更新到跳转后的地方*/

		}
		else {/*不是跳转*/
			for (j = 0; j < buff[0]; j++) {/*此时格式是buff指向字节是一个数，表明后面域名字节的个数*/
				temp[count + j] = buff[j + 1];/*一个字节一个字节拷贝，此处可用memcpy*/
			}
			temp[count + j] = '.';/*拷贝后，加上一个'.'*/
			count += buff[0] + 1;/*计数器更新，增加量为域名字节数以及一个点所占字节（1）*/
			buff += buff[0] + 1;/*buff指针更新到下一个地址，可能是一个数或者c0跳转指令*/
		}
	}
	if (count <= 0) {/*debug用，出现了意外情况（正常情况下不会有空域名或者count为负数情况）*/
		printf("count==0! wrong.\n");
		return NULL;
	}
	ret = (unsigned char*)malloc(sizeof(char) * (count));
	memcpy(ret, temp, count);
	ret[count - 1] = '\0';
	/*申请内存，将缓存区内存拷贝到申请内存地址上，将末尾的'.'替换为\0，代表字符串的末尾*/
	return ret;
}
static unsigned int domainInverseAnalyze(unsigned char* dst, unsigned char* src) {/*把src处点分域名字符串转换为dns报文中的格式,写入dst，如www.baidu.com\0转换为\03www\05baidu\03com，返回转换后有效长度*/
	int i, j, len;//i，j为遍历变量，len为点分字符串长度

	len = strlen(src);
	if (len <= 1) {/*特殊情况，空串*/
		dst[0] = 0;
		return 1;
	}
	else {
		memcpy(dst + 1, src, (long long)len + 1);
		for (i = 0, j = 1; dst[j] != '\0'; j++) {/*根据'.'的位置来写入字符个数，注意src的第一个字节不是'.'，但是这个位置要写数，所以在写入dst前时整体向后移动一个字节，相当于人为加了一个'.'*/
			if (dst[j] == '.') {
				dst[i] = j - i - 1;
				i = j;
			}
		}
		dst[i] = j - i - 1;/*最后一段后面没有'.',单独添加*/
		return j + 1;/*等同len+2(多两个一个是末尾0一个是最前面的数)*/
	}
}
unsigned int dataToDns(unsigned char* buff, struct DNS* dns) {//函数用于把buff指针所指向的原始dns报文转换为本程序中可识别的格式，变得容易读取，包括域名部分的解压缩（c0跳转指令）。返回原始dns报文长度
	unsigned int i, offset, domainlen;/*i为遍历量，offset代表当前处理位置的偏移量，domainlen表示当前处理对象（域名）在报文中的长度（不算跳转）*/
	/*开始拷贝头字段*/
	myMemcpy((unsigned char*)&(dns->id), (void*)buff, 2);/*拷贝id字段，这里使用myMemcpy是因为大小端格式的问题*/
	myMemcpy((unsigned char*)&(dns->question_num), buff + 4, 2);/*拷贝四个数字字段*/
	myMemcpy((unsigned char*)&(dns->answer_num), buff + 6, 2);
	myMemcpy((unsigned char*)&(dns->authority_num), buff + 8, 2);
	myMemcpy((unsigned char*)&(dns->additional_num), buff + 10, 2);
	dns->flag.qr = (buff[2] & 0x80) >> 7;/*拷贝flag字段，一共8个标识*/
	dns->flag.opcode = (buff[2] & 0x78) >> 3;
	dns->flag.aa = (buff[2] & 0x04) >> 2;
	dns->flag.tc = (buff[2] & 0x02) >> 1;
	dns->flag.rd = (buff[2] & 0x01);
	dns->flag.ra = (buff[3] & 0x80) >> 7;
	dns->flag.z = 0;/*预留字段，可以省略*/
	dns->flag.rcode = (buff[3] & 0x0f);
	/*头字段拷贝完成*/
	/*开始拷贝问题、回答字段*/
	/*首先申请空间*/
	if (dns->question_num > 0) {
		dns->que = (struct QUE*)malloc(sizeof(struct QUE) * dns->question_num);
	}
	else {
		dns->que = NULL;
	}/*question字段不为空，申请空间，否则赋值空指针*/
	if (dns->answer_num > 0) {
		dns->ans = (struct RR*)malloc(sizeof(struct RR) * dns->answer_num);
	}
	else {
		dns->ans = NULL;
	}/*answer字段不为空，申请空间，否则赋值空指针*/
	if (dns->authority_num > 0) {
		dns->aut = (struct RR*)malloc(sizeof(struct RR) * dns->authority_num);
	}
	else {
		dns->aut = NULL;
	}/*authority字段不为空，申请空间，否则赋值空指针*/
	if (dns->additional_num > 0) {
		dns->add = (struct RR*)malloc(sizeof(struct RR) * dns->additional_num);
	}
	else {
		dns->add = NULL;
	}/*addtional字段不为空，申请空间，否则赋值空指针*/
	/*4个字段申请空间完毕*/
	/*开始依次对每个空间赋值*/
	for (i = 0, offset = 12; i < dns->question_num; i++) {
		/*首先提取域名*/
		if ((buff[offset] & 0xc0) != 0xc0) {/*不是跳转指令*/
			domainlen = strlen(buff + offset);/*计算domain长度*/
			dns->que[i].domain = domainAnalyze(buff + offset, buff);/*解析domain字段，赋值解析后的字符串*/
			offset += domainlen + 1;/*offset更新，跳过domain字段，这里+1是因为strlen没算\0*/
			myMemcpy((unsigned char*)&(dns->que[i].type), buff + offset, 2);/*分别拷贝type和class字段*/
			myMemcpy((unsigned char*)&(dns->que[i].class), buff + offset + 2, 2);
			offset += 4;/*偏移量更新，跳过class和type字段*/
		}
		else {/*是跳转指令*/
			dns->que[i].domain = domainAnalyze(buff + offset, buff);/*同上，解析domain字段，偏移量只跳2个字节*/
			offset += 2;
			myMemcpy((unsigned char*)&(dns->que[i].type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->que[i].class), buff + offset + 2, 2);
			offset += 4;
		}
	}
	/*question区域提取完毕*/
	for (i = 0; i < dns->answer_num; i++) {
		/*首先提取域名*/
		/*对query区域的代码注解如上*/
		if ((buff[offset] & 0xc0) != 0xc0) {/*不是跳转指令*/
			domainlen = strlen(buff + offset);
			dns->ans[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += domainlen + 1;
			myMemcpy((unsigned char*)&(dns->ans[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->ans[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		else {/*是跳转指令*/
			dns->ans[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += 2;
			myMemcpy((unsigned char*)&(dns->ans[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->ans[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		/*域名，class，type提取完毕*/
		/*开始拷贝RRS字段*/
		myMemcpy((unsigned char*)&(dns->ans[i].ttl), buff + offset, 4);/*拷贝ttl和len字段*/
		myMemcpy((unsigned char*)&(dns->ans[i].len), buff + offset + 4, 2);
		/*ttl,len拷贝完毕*/
		dns->ans[i].resource = (unsigned char*)malloc(sizeof(char) * (dns->ans[i].len));/*根据len字段申请空间*/
		memcpy((dns->ans[i].resource), buff + offset + 6, dns->ans[i].len);/*将resource字段拷贝，注意这里不解析，因为这里不光可能是域名，还可能是IP地址等等，对此区域的处理交给上层模块*/
		offset += 6 + dns->ans[i].len;/*offset更新，跳过ttl，len和资源部分*/
		if (dns->ans[i].que.class == 1 && dns->ans[i].que.type == 5) {/*假如是cname，就把资源部分解析*/
			dns->ans[i].resource_string = domainAnalyze(dns->ans[i].resource, buff);
		}
		else {
			dns->ans[i].resource_string = NULL;
		}
	}
	/*按如上方法提取剩下两个区域，注解如上*/
	for (i = 0; i < dns->authority_num; i++) {
		/*首先提取域名*/
		if ((buff[offset] & 0xc0) != 0xc0) {/*不是跳转指令*/
			domainlen = strlen(buff + offset);

			dns->aut[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += domainlen + 1;
			myMemcpy((unsigned char*)&(dns->aut[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->aut[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		else {/*是跳转指令*/
			dns->aut[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += 2;
			myMemcpy((unsigned char*)&(dns->aut[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->aut[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		/*域名，class，type提取完毕*/
		myMemcpy((unsigned char*)&(dns->aut[i].ttl), buff + offset, 4);
		myMemcpy((unsigned char*)&(dns->aut[i].len), buff + offset + 4, 2);
		/*ttl,len拷贝完毕*/
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
		/*首先提取域名*/
		if ((buff[offset] & 0xc0) != 0xc0) {/*不是跳转指令*/
			domainlen = strlen(buff + offset);
			dns->add[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += domainlen + 1;
			myMemcpy((unsigned char*)&(dns->add[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->add[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		else {/*是跳转指令*/
			dns->add[i].que.domain = domainAnalyze(buff + offset, buff);
			offset += 2;
			myMemcpy((unsigned char*)&(dns->add[i].que.type), buff + offset, 2);
			myMemcpy((unsigned char*)&(dns->add[i].que.class), buff + offset + 2, 2);
			offset += 4;
		}
		/*域名，class，type提取完毕*/
		myMemcpy((unsigned char*)&(dns->add[i].ttl), buff + offset, 4);
		myMemcpy((unsigned char*)&(dns->add[i].len), buff + offset + 4, 2);
		/*ttl,len拷贝完毕*/
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
	/*全部提取完毕*/
	return offset;
}
unsigned char* dnsToData(struct DNS* dns, unsigned int* len) {
	int i, j, offset, domainlen, infonum;/*i，j为遍历量，offset为遍历内存时所用遍历量，domianlen为domain区域长度，infonum为info数组的遍历量*/
	unsigned char temp[2048];
	unsigned char* ret;
	struct COMPRESS_INFO info[200];/*用于报文的压缩，对报文中domain区域以及cname区域中重复的字符串，用c0跳转表示，结构体中offset在next为-1时真正有效，next为-1代表对应字符串第一次出现，next不为-1时其值为记录该字符串第一次出现的结构体的下标*/
	memset(temp, 0, sizeof(temp));/*缓存清零*/
	for (i = 0, infonum = 0; i < dns->question_num; i++) {
		if (dns->que[i].class == 1 && dns->que[i].type == 1) {/*初始化操作，针对ipv4，ip地址查询*/
			info[infonum].name = dns->que[i].domain;
			info[infonum].next = -1;
			info[infonum].offset = 0;
			infonum++;
		}
	}
	for (i = 0; i < dns->answer_num; i++) {
		/*初始化操作，针对ipv4，ip地址应答和cname应答*/
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

	for (i = 0; i < infonum; i++) {/*遍历所有有效信息，采用类似选择排序的方法，遍历每个字符串是否与其他串匹配，匹配之后标志位（next）就不为-1了，再遇到的时候直接跳过，减少时间，在所有串相同的情况下时间复杂度O(n),所有串不同情况下O(n^2)*/
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


	/*首先拷贝头字段*/
	/*先拷贝头部id和四个数字字段*/

	myMemcpy(temp, (unsigned char*)(&dns->id), 2);
	myMemcpy(temp + 4, (unsigned char*)(&dns->question_num), 2);
	myMemcpy(temp + 6, (unsigned char*)(&dns->answer_num), 2);
	myMemcpy(temp + 8, (unsigned char*)(&dns->authority_num), 2);
	myMemcpy(temp + 10, (unsigned char*)(&dns->additional_num), 2);
	/*z之后拷贝flag字段*/
	temp[2] = 0; temp[3] = 0;//先全赋值0
	temp[2] |= (dns->flag.qr << 7);
	temp[2] |= (dns->flag.opcode << 3);
	temp[2] |= (dns->flag.aa << 2);
	temp[2] |= (dns->flag.tc << 1);
	temp[2] |= (dns->flag.rd);
	temp[3] |= (dns->flag.ra << 7);
	temp[3] |= (dns->flag.rcode);
	/*flag字段拷贝完毕*/

	for (i = 0, infonum = 0, offset = 12; i < dns->question_num; i++) {
		/*拷贝query*/
		if (dns->que[i].class == 1 && dns->que[i].type == 1) {
			info[infonum].offset = offset;/*对第一个问题区域，只记录偏移量，不真正压缩*/
			infonum++;
		}
		domainlen = domainInverseAnalyze(temp + offset, dns->que[i].domain);
		offset += domainlen;
		myMemcpy(temp + offset, (unsigned char*)&(dns->que[i].type), 2);
		myMemcpy(temp + offset + 2, (unsigned char*)&(dns->que[i].class), 2);
		offset += 4;
	}
	for (i = 0; i < dns->answer_num; i++) {
		/*拷贝query*/
		/*在应答区域，不光记录串对应偏移，也要压缩*/
		if (info[infonum].next == -1) {/*对应字符串第一次出现*/
			info[infonum].offset = offset;
			domainlen = domainInverseAnalyze(temp + offset, dns->ans[i].que.domain);
			offset += domainlen;
			infonum++;
		}
		else {/*不是第一次出现，那么用c0跳转，偏移量为当前info[infonum]的next所记录的offset,拷贝注意大小端，所以用myMemcpy*/
			myMemcpy(temp + offset, (unsigned char*)&(info[info[infonum].next].offset), 2);
			temp[offset] |= 0xc0;/*相当于前面写上c0*/
			offset += 2;
			infonum++;
		}
		myMemcpy(temp + offset, (unsigned char*)&(dns->ans[i].que.type), 2);
		myMemcpy(temp + offset + 2, (unsigned char*)&(dns->ans[i].que.class), 2);
		offset += 4;
		/*拷贝RRS*/
		myMemcpy(temp + offset, (unsigned char*)&(dns->ans[i].ttl), 4);/*拷贝ttl*/
		if (dns->ans[i].que.type == 5 && dns->ans[i].que.class == 1) {/*如果是cname应答*/
			if (info[infonum].next == -1) {/*不跳转*/
				info[infonum].offset = offset + 6;/*记录偏移*/
				dns->ans[i].len = strlen(dns->ans[i].resource_string) + 2;/*写入长度*/
				myMemcpy(temp + offset + 4, (unsigned char*)&(dns->ans[i].len), 2);/*长度部分写入缓存*/
				dns->ans[i].resource = (unsigned char*)malloc(sizeof(char) * dns->ans[i].len);/*分配一个空间临时用*/
				domainInverseAnalyze(dns->ans[i].resource, dns->ans[i].resource_string);/*把string对应部分逆转换过去*/
				memcpy(temp + offset + 6, (dns->ans[i].resource), dns->ans[i].len);/*逆转换部分写进缓存*/
				free(dns->ans[i].resource);/*释放这部分临时用的空间*/
				infonum++;
			}
			else {
				dns->ans[i].len = 2;/*跳转，则长度为2*/
				myMemcpy(temp + offset + 4, (unsigned char*)&(dns->ans[i].len), 2);/*写入长度和偏移*/
				myMemcpy(temp + offset + 6, (unsigned char*)&(info[info[infonum].next].offset), 2);
				temp[offset + 6] |= 0xc0;/*加上头部的c0*/
				infonum++;
			}
		}
		else {/*不是cname型，直接拷贝对应字节*/
			myMemcpy(temp + offset + 4, (unsigned char*)&(dns->ans[i].len), 2);
			memcpy(temp + offset + 6, (dns->ans[i].resource), dns->ans[i].len);
		}
		offset += dns->ans[i].len + 6;
	}
	/*下面的操作逻辑同上*/
	for (i = 0; i < dns->authority_num; i++) {
		/*拷贝query*/
		domainlen = domainInverseAnalyze(temp + offset, dns->aut[i].que.domain);
		offset += domainlen;
		myMemcpy(temp + offset, (unsigned char*)&(dns->aut[i].que.type), 2);
		myMemcpy(temp + offset + 2, (unsigned char*)&(dns->aut[i].que.class), 2);
		offset += 4;
		/*拷贝RRS*/
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
		/*拷贝query*/
		domainlen = domainInverseAnalyze(temp + offset, dns->add[i].que.domain);
		offset += domainlen;
		myMemcpy(temp + offset, (unsigned char*)&(dns->add[i].que.type), 2);
		myMemcpy(temp + offset + 2, (unsigned char*)&(dns->add[i].que.class), 2);
		offset += 4;
		/*拷贝RRS*/
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
	/*转换完毕*/
	*len = offset;/*最后的offset就是有效长度*/
	ret = (unsigned char*)malloc(sizeof(char) * offset);/*分配空间，用于返回*/
	memcpy(ret, temp, offset);/*拷贝内存*/
	return ret;
}
void freeDns(struct DNS* dnsptr) {
	/*函数实现对dnsptr指向的DNS数据块进行清除操作，释放占用的内存，并将整个DNS数据块清零*/
	int i;/*依次释放对于区域*/
	for (i = 0; i < dnsptr->question_num; i++) {
		free(dnsptr->que[i].domain);/*问题部分释放*/
	}
	dnsptr->que = NULL;
	for (i = 0; i < dnsptr->answer_num; i++) {
		free(dnsptr->ans[i].que.domain);/*回答的问题部分释放*/
		if (dnsptr->ans[i].que.type == 5 && dnsptr->ans[i].que.class == 1) {/*如果是cname，resource无效，string有效，释放string，否则释放resource*/
			free(dnsptr->ans[i].resource_string);
		}
		else {
			free(dnsptr->ans[i].resource);
		}
	}
	dnsptr->ans = NULL;
	for (i = 0; i < dnsptr->authority_num; i++) {/*释放逻辑同上*/
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
	memset(dnsptr, 0, sizeof(struct DNS));/*最后把整个报文区域清零（数据清零，指针变成NULL）*/
}