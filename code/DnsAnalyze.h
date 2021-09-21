
unsigned int dataToDns(unsigned char* buff, struct DNS* dns);/*将buff指向的原始DNS报文转换为程序内定义的可读DNS报文，写入dns指向的内存中，返回原始DNS报文的有效长度*/
unsigned char* dnsToData(struct DNS* dns, unsigned int* len);/*将dns指向的可读DNS报文转换为原始DNS报文，分配空间，将转换后的原始DNS报文地址返回，有效长度写入len指向内存（转换过程使用c0指令，对完全相同的字符串部分进行压缩）*/
void freeDns(struct DNS* dnsptr);/*函数实现对dnsptr指向的DNS数据块进行清除操作，释放占用的内存，并将整个DNS数据块清零*/
