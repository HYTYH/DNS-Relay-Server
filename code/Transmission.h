void DEBUG(void); /*����ִ�п�ʼǰ��ӡ�����Ϣ����ɾȥ��*/
void transInfoFlush(void);/*idת��ģ�黺��ˢ�£�ȥ�����ڵļ�¼*/
void transInfoInit(void);/*idת��ģ���ʼ��������ռ��Լ���ʼ����ֵ*/
void networkConnectionInit(void);/*��������ģ���ʼ�������sock�ţ���ip��port*/
void sendDns(unsigned char* buff, int len);/*����ԭʼDNS���ģ�������buffָ���ڴ��У�������Ч����Ϊlen���������ݱ��������Զ�ѡ����Ŀ���Լ�����idת��*/
int recieveDns(unsigned char* buff);/*���մ��ⲿ������ԭʼDNS����,���ݰ��������ж���Դ���Բ�ѯ������id��֮��д��buffָ���ڴ��У�������Ч����*/