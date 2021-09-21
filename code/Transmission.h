void DEBUG(void); /*程序执行开始前打印相关信息（可删去）*/
void transInfoFlush(void);/*id转换模块缓存刷新，去除过期的记录*/
void transInfoInit(void);/*id转换模块初始化，分配空间以及初始化赋值*/
void networkConnectionInit(void);/*网络连接模块初始化，获得sock号，绑定ip和port*/
void sendDns(unsigned char* buff, int len);/*发送原始DNS报文，报文在buff指向内存中，发送有效长度为len，函数根据报文内容自动选择发送目的以及进行id转换*/
int recieveDns(unsigned char* buff);/*接收从外部发来的原始DNS报文,根据包的类型判断来源，对查询包更改id，之后写入buff指向内存中，返回有效长度*/