#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <stdint.h>

#define CACHE_BUFF_SIZE 		4096
#define MC_PORT                	9980
#define TIME_INTEVAL 			5
#define PATH_STR_LEN 			256

#define FC_LOG_FILE	"/var/log/fc-leakscan.log"


#define MSG_BASE_REGISTRE_REQ         1001  // �ڵ�ע������
#define MSG_BASE_REGISTRE_RST         1002  // �ڵ�ע����Ӧ
#define MSG_BASE_AUTH_REQ             1003  // �ڵ���֤����
#define MSG_BASE_AUTH_RST             1004  // �ڵ���֤��Ӧ
#define MSG_BASE_HEARTBEAT_REQ        1005  // ��������
#define MSG_BASE_HEARTBEAT_RST        1006  // ������Ӧ
#define MSG_BASE_SYS_REBOOT_REQ       1007  // �豸��������
#define MSG_BASE_SYS_REBOOT_RST       1008  // �豸������Ӧ


#define MAX_RECV_BUF_SIZE           4*1024*1024
#define RECV_BUF_HEAD               0
#define RECV_BUF_BODY               1

#define MSG_RST_OK                "OK"
#define MSG_RST_FAILED            "FAILED"

#define NODE_TYPE                 "fc-leakscan"

#define  WAF_CFG_NAME  		"/etc/firecloud/conf/common/firecloud_mc.conf"
#define  NODE_INFO_FILE		"/etc/firecloud/waf_node.conf"

#define SYS_NETWORK_FILE_BASE     "/etc/sysconfig/network-scripts/ifcfg-"

typedef struct _IF_IPV4
{
    char if_name[64];
    char ip_addr[32];
    char hd_addr[32];

    struct _IF_IPV4 *next;
}IF_IPV4;


typedef struct _CPU_TIME
{
    long user;
    long nice;
    long system;
    long idle;
    long irq;
    long softirq;
    long guest;
} CPU_TIME;


/* ��Ϣͷ */
typedef struct _MSG_HEADS
{
    int32_t msgid; // ��ϢID
    int32_t node_id;// ��ȫ������ϵͳ��ģ��ID
    int32_t sn;// �Ự���кţ���֤����������ֵ����֮��ÿ�������к�+1
    unsigned char check_sum[32];  // hmacЧ�飬 ���Լ�����������ݰ�����Ϣͷ����Ϣ��
    int32_t len;//  ��Ϣ�峤��
}MSG_HEADS;


/* �ڵ���֤��Ϣ�� */
//type: fc-firewall, fc-ids, fc-ips, fc-webchk, fc-whitelist, fc-leekscan, fc-proto-parse
typedef struct _NODE_AUTH
{
    char type[32];
    char ip[32];
    char mac[32]; 
}NODE_AUTH;


/* ��������Ϣ�� */
typedef struct _HEART_BEAT
{
    char cpu[64];
    char mem[32];
    char disk[32];
}HEART_BEAT;


/* ����������Ϣ�� */
typedef struct _SYS_NETWORK
{
    char id[32+ 1];
    char ipaddr[32 + 1]; 
    char netmask[32 + 1];  // "xxx.xxx.xxx.xxx"
}SYS_NETWORK;


/* ʱ��������Ϣ��*/
typedef struct _SYS_TIME
{
    char id[32];
    char datetime[24];
}SYS_TIME;


/* ͨ����Ӧ����Ϣ�� */
typedef struct _RSP_BODY
{
    char result[8]; // OK, FAILED
    char describe[256]; //��֤�ɹ�ʱ�����ֶ�Ϊ�ڵ�����
}RSP_BODY;


int checkprogramisrun(const char *pName);


int connect_server(void);

//��ȡ��������
int node_get_db_config(void);

const char* msgid2str(int32_t msgid);

#endif
