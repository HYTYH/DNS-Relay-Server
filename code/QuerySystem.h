void debugDomainCname(void);/*debug����*/
void debugCnameIp(void);/*debug����*/
void recordInit(void);/*domain-ipת�����ܵĳ�ʼ��,���Ԥ����Ϣ*/
int queryDomainIp(struct DNS* dst, struct DNS src);/*��ѯsrc��ӦDNS��query���ֵ�ip��ѯ�������д��dst��DNS��ȥ����ѯʧ���򷵻�0���ɹ�����1*/
void domainIpRecordFlush(void);/*ˢ��Domian-ip��������������ڼ�¼����̬���������С��ʹ��ά�ֽϸ߿ռ�������ͬʱ��֤����*/
void addDomainIp(struct DNS dns);/*��dns��Ӧ��domain-cname��ѯ�����cname-ip���������ѯ��¼��*/
