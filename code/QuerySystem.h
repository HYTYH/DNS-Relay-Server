void debugDomainCname(void);/*debug所用*/
void debugCnameIp(void);/*debug所用*/
void recordInit(void);/*domain-ip转换功能的初始化,添加预设信息*/
int queryDomainIp(struct DNS* dst, struct DNS src);/*查询src对应DNS中query部分的ip查询，将结果写入dst处DNS中去，查询失败则返回0，成功返回1*/
void domainIpRecordFlush(void);/*刷新Domian-ip缓存区域，清除过期记录，动态调整缓存大小，使其维持较高空间利用率同时保证速率*/
void addDomainIp(struct DNS dns);/*将dns对应的domain-cname查询结果和cname-ip结果添加入查询记录中*/
