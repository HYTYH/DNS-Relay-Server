
unsigned int dataToDns(unsigned char* buff, struct DNS* dns);/*��buffָ���ԭʼDNS����ת��Ϊ�����ڶ���Ŀɶ�DNS���ģ�д��dnsָ����ڴ��У�����ԭʼDNS���ĵ���Ч����*/
unsigned char* dnsToData(struct DNS* dns, unsigned int* len);/*��dnsָ��Ŀɶ�DNS����ת��ΪԭʼDNS���ģ�����ռ䣬��ת�����ԭʼDNS���ĵ�ַ���أ���Ч����д��lenָ���ڴ棨ת������ʹ��c0ָ�����ȫ��ͬ���ַ������ֽ���ѹ����*/
void freeDns(struct DNS* dnsptr);/*����ʵ�ֶ�dnsptrָ���DNS���ݿ��������������ͷ�ռ�õ��ڴ棬��������DNS���ݿ�����*/
