#include <event2/event_struct.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/util.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include "util-pconf.h"
#include "client.h"
#include "debug_log.h"
#include "hmac_sha2.h"
#include "sm4ende.h"



#define TIME_INTEVAL 5

#define MSG_BASE_REGISTRE_REQ         1001  // 节点注册请求
#define MSG_BASE_REGISTRE_RST         1002  // 节点注册响应
#define MSG_BASE_AUTH_REQ             1003  // 节点认证请求
#define MSG_BASE_AUTH_RST             1004  // 节点认证响应
#define MSG_BASE_HEARTBEAT_REQ        1005  // 心跳请求
#define MSG_BASE_HEARTBEAT_RST        1006  // 心跳响应
#define MSG_BASE_SYS_REBOOT_REQ       1007  // 设备重启请求
#define MSG_BASE_SYS_REBOOT_RST       1008  // 设备重启响应




#define MAX_RECV_BUF_SIZE           4*1024*1024
#define RECV_BUF_HEAD               0
#define RECV_BUF_BODY               1



#define MSG_RST_OK                "OK"
#define MSG_RST_FAILED            "FAILED"

#define NODE_TYPE_FIREWALL        "fc-firewall"
#define NODE_TYPE_LEAKSCAN        "fc-leakscan"


#define SYS_NETWORK_FILE_BASE     "/etc/sysconfig/network-scripts/ifcfg-"
//#define FC_NODE_FILE                "/etc/firecloud/conf/common/firecloud_mc.conf"
#define FC_NODE_FILE                "/etc/firecloud/fc_node.conf"



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


/* 消息头 */
typedef struct _MSG_HEADS
{
    int32_t msg_id; // 消息ID
    int32_t node_id;// 安全部件子系统或模块ID
    int32_t sn;// 会话序列号，认证后产生（随机值），之后每个包序列号+1
    unsigned char check_sum[32];  // hmac效验， 除自己外的所有数据包括消息头和消息体
    int32_t body_len;//  消息体长度
}MSG_HEADS;



/* 节点认证消息体 */
//type: fc-firewall, fc-ids, fc-ips, fc-webchk, fc-whitelist, fc-leekscan, fc-proto-parse
typedef struct _NODE_AUTH
{
    char type[32];
    char ip[32];
    char mac[32]; 
}NODE_AUTH;


/* 心跳包消息体 */
typedef struct _HEART_BEAT
{
    char cpu[64];
    char mem[32];
    char disk[32];
}HEART_BEAT;


/* 网络配置消息体 */
typedef struct _SYS_NETWORK
{
    char id[32+ 1];
    char ipaddr[32 + 1]; 
    char netmask[32 + 1];  // "xxx.xxx.xxx.xxx"
}SYS_NETWORK;


/* 时间设置消息体*/
typedef struct _SYS_TIME
{
    char id[32];
    char datetime[24];
}SYS_TIME;


/* 通用响应包消息体 */
typedef struct _RSP_BODY
{
    char result[8]; // OK, FAILED
    char describe[256]; //认证成功时，该字段为节点名称
}RSP_BODY;



char g_dbaddr[32] = {0};
char g_dbport[16] = {0};
char g_dbname[32] = {0};
char g_dbuser[32] = {0};
char g_dbpass[32] = {0};

char g_mc_addr[32] = {0};
char g_mc_port[16] = {0};



IF_IPV4 *g_if_info = NULL;

static struct event_base *g_base = NULL;
struct sockaddr_in g_server;
static struct event_base *g_timed_base = NULL;
int g_socket_status = 0;
int g_auth = 0;
unsigned int g_sn = 0;

int32_t  g_node_id = 0;
char g_node_name[64+ 1] = {0};
char g_node_ip[64] = {0};
char g_node_netmask[64] = {0};
char g_node_mac[64] = {0};
char g_node_devname[64] = {0};

char *g_recv_buf = NULL;
char *g_recv_dec_buf = NULL;


char *g_send_buf = NULL;
int g_send_buf_size = 0;



unsigned char g_hmackey[20] = 
{ 
    0x23, 0xa7, 0xb9, 0x87, 0x43, 0xc3, 0xb1, 0x8d, 0x2a, 0x8c,
    0xc9, 0x9e, 0xb7, 0x2a, 0xab, 0xca, 0xea, 0xe8, 0x2a, 0xc9  
};

unsigned char g_sm4key[16] = 
{
    0xa3, 0xc8, 0x9e, 0x17, 0x53, 0xab, 0xe2, 0x3a,
    0x7c, 0x5a, 0x2c, 0x4a, 0x2b, 0x40, 0x3a, 0xc8
};

static void sleep_ms(unsigned long secs)
{
    struct timeval tval;
    
    tval.tv_sec = secs / 1000;
    tval.tv_usec = (secs * 1000) % 1000000;
    select(0, NULL, NULL, NULL, &tval);
}

static int  sys_if_to_link (struct ifaddrs *ifap, char *buf)
{
    IF_IPV4 *if_node = NULL;

    for(if_node = g_if_info; if_node != NULL; if_node = if_node->next)
    {
        if(!strcmp(if_node->if_name, ifap->ifa_name))
            break;
    }
    
    if(if_node == NULL)
    {  
        if_node = (IF_IPV4 *)malloc(sizeof(IF_IPV4));
        if(if_node == NULL)
        {
            printf("malloc failed\n");
            return -1;
        }

        memset(if_node, 0, sizeof(IF_IPV4));
        if_node->next = g_if_info;
        strcpy(if_node->if_name, ifap->ifa_name);
        g_if_info = if_node;
    }
    
    switch(ifap->ifa_addr->sa_family)
    {
    case AF_INET:
        strcpy (if_node->ip_addr, buf);
        //printf ("head %s\n", if_node->ip_addr);
        break;
    case AF_PACKET:
        strcpy (if_node->hd_addr, buf);
        //printf ("head %s\n", if_node->hd_addr);
        break;
    default:
        break;
    }

    return 0;
} 

int sys_if_prt(struct sockaddr *ifa_addr, char *addrbuf, int bufsize)
{
    memset (addrbuf, 0, bufsize);
    struct sockaddr_ll *s;
    int i, len, ret = 0;;
    int family = ifa_addr->sa_family;

    switch (family)
    {
        case AF_INET: 
        inet_ntop(ifa_addr->sa_family, &((struct sockaddr_in *)ifa_addr)->sin_addr,
                addrbuf, sizeof (struct sockaddr_in));
        break;
        
        case AF_PACKET:
        s = (struct sockaddr_ll *)ifa_addr;
        for (i=0,len=0; i<6; i++)
            len += sprintf (addrbuf+len, "%02x%s", s->sll_addr[i], i<5?":":" ");
        break;
        
        default:
            ret = -1;
        break;
    }
    
    return ret;
}

void sys_if_printf()
{
    IF_IPV4 *if_node = NULL;
    
    for(if_node = g_if_info; if_node != NULL;if_node = if_node->next)
        printf("%s: %s  %s\n", if_node->if_name, strlen(if_node->ip_addr)>0?if_node->ip_addr:"No ip addr", if_node->hd_addr);
    
}

void sys_if_free()
{
    IF_IPV4 *if_node = NULL;
    
    for(if_node = g_if_info; if_node != NULL;if_node = g_if_info)
    {
        g_if_info = g_if_info->next;
        free(if_node);
    } 
    
}

int sys_if_get()
{
    char buf[64];
    struct ifaddrs *ifa, *ifap;

    if (getifaddrs (&ifa) == -1)
    {
        perror (" getifaddrs\n");
        return -1;
    }
    
    for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next)
    {
        if(strcmp (ifap->ifa_name, "lo") == 0)
            continue; /* skip the lookback card */

        if(ifap->ifa_addr == NULL)
            continue; /* if addr is NULL, this must be no ip address */

        if(sys_if_prt(ifap->ifa_addr, buf, sizeof(buf)) == 0)
        {
            sys_if_to_link(ifap, buf);
            //sys_if_to_link_bak(ifap, buf);
        }
    }
    
    freeifaddrs (ifa);
    
    return 0;
}

void sys_if_reload()
{
    sys_if_free();
    sys_if_get();
    //sys_if_printf();
}

IF_IPV4 * sys_if_search_from_ip(char *ip)
{
    IF_IPV4 *if_node = NULL;
    
    for(if_node = g_if_info; if_node != NULL;if_node = if_node->next)
    {
        if(!strcmp(if_node->ip_addr, ip))
            return if_node;
            
    }

    return NULL;
}


// 通过已经连接的TCP SOCK 获取自己的IP
int sys_get_addr()
{
	struct sockaddr_in addSend;
    int sockSend;
    socklen_t n = sizeof(addSend);

    memset(g_node_ip, 0, sizeof(g_node_ip));
	sockSend = socket(AF_INET,SOCK_STREAM,0);
	addSend.sin_family = AF_INET;
	addSend.sin_addr.s_addr = inet_addr(g_mc_addr);
	addSend.sin_port=htons(atoi(g_mc_port));

	if(connect(sockSend,(struct sockaddr *)&addSend, sizeof(addSend)) == -1)
	{
		log_error("connect to %s failed. %s\n", "", strerror(errno));
        close(sockSend);
		return -1;
	}

    //getpeername(sockSend, (struct sockaddr *)&addSend, &n);
    getsockname(sockSend, (struct sockaddr *)&addSend, &n);
    strcpy(g_node_ip, inet_ntoa(addSend.sin_addr));
    log_debug("g_node_ip=%s", g_node_ip);
    close(sockSend);

	return 0;
}

void sys_get_cpu_time(CPU_TIME *cputime)
{
    FILE *state;
    char tbuff[1024] = {0};
    
    if (!(state = fopen("/proc/stat", "r")))
        return;
    
    if (fgets(tbuff, sizeof(tbuff) - 1, state) == NULL)
    {
        fclose(state);
        return;
    }
    
    fclose(state);
    sscanf(tbuff, "%*s %ld %ld %ld %ld %ld %ld %ld", &(cputime->user), &(cputime->nice), &(cputime->system), &(cputime->idle), &(cputime->irq), &(cputime->softirq), &(cputime->guest));
}

double sys_get_cpu_rate()
{
    CPU_TIME time1;
    CPU_TIME time2;
    double rate;
    long total;
    long idle;
    
    sys_get_cpu_time(&time1);
    sleep_ms(300);
    sys_get_cpu_time(&time2);
    total = (time2.user - time1.user) + (time2.nice - time2.nice) + (time2.system - time1.system) + (time2.idle - time1.idle) + (time2.irq - time1.irq) + (time2.softirq - time1.softirq) + (time2.guest - time1.guest);
    idle = time2.idle - time1.idle;
    log_trace("time1: %ld %ld %ld %ld %ld %ld %ld", time1.user, time1.nice, time1.system, time1.idle, time1.irq, time1.softirq, time1.guest);
    log_trace("time2: %ld %ld %ld %ld %ld %ld %ld", time2.user, time2.nice, time2.system, time2.idle, time2.irq, time2.softirq, time2.guest);
    log_trace("cpu total: %ld", total);
    log_trace("cpu idle: %ld", idle);
    if (total == 0)
        return 0.0;

    rate = (total - idle) * 1.0 / total * 100;
    
    return rate;
}

double sys_get_mem_rate()
{
    FILE *mem;
    unsigned long total;
    unsigned long free;
    char mbuff[1024] = {0};
    double rate;
    
    if (!(mem = fopen("/proc/meminfo", "r")))
        return 0.0;

    if (fgets(mbuff, sizeof(mbuff) - 1, mem) == NULL)
    {
        fclose(mem);
        return 0.0;
    }
    sscanf(mbuff, "%*s %lu %*s", &total);
    
    if (fgets(mbuff, sizeof(mbuff) - 1, mem) == NULL)
    {
        fclose(mem);
        return 0.0;
    }
    fclose(mem);
    sscanf(mbuff, "%*s %lu %*s", &free);
    rate = (1.0 - (double)free / (double)total) * 100;
    
    return rate;
}

double sys_get_disk_rate()
{
    char cmd[1024] = {0};
    char buf[1024] = {0};
    unsigned long long total = 0;
    unsigned long long use = 0;
    unsigned long long dev_total = 0;
    unsigned long long dev_use = 0;
    FILE *disk = NULL; 
    double rate;   

    snprintf(cmd, sizeof(cmd), "df -h -BM");
    if((disk = popen(cmd, "r")) == NULL){
        return -1;
    }

    if(NULL == fgets(buf, sizeof(buf), disk)){
        pclose(disk);
        return 0.0;
    }

    while (NULL != fgets(buf, sizeof(buf), disk))
    {  
        sscanf(buf,"%*s %llu %*s %llu %*s",
            &dev_total,
            &dev_use);  
        total += dev_total;
        use += dev_use;   
        //log_trace("current total size: %llu, use size: %llu", dev_total, dev_use);
    }
    pclose(disk);
    rate = ((double)use / (double)total) * 100; 
    log_trace("current disk rate: %f , use: %llu, total: %llu", rate, use, total);  
    
    return rate;
}


int sys_time_set(char *datetime)
{
	struct timeval tv;


	tv.tv_sec = atoi(datetime);
	tv.tv_usec = 0;
	if(settimeofday(&tv, NULL) < 0)
	{
		log_error("sys_time_set failed.");
		return -1;
	}

    system("hwclock -w");

	return 0;
}

void sys_reset()
{
    log_debug("reboot started!");
    system("reboot");
}

void sys_off()
{
    log_debug("poweroff started!");
    system("poweroff");
}

int sys_network_update(const char *if_name, const char *ip, const char *netmask)
{
    char if_file[512] = {0};
    char buf[1024] = {0};
    char line[256] = {0};
    const char *ip_flag = "IPADDR";
    const char *netmask_flag = "NETMASK";
    FILE *pf = NULL;
    

    sprintf(if_file, "%s%s", SYS_NETWORK_FILE_BASE, if_name);
    if ((pf = fopen(if_file, "r+b")) == NULL)
	{
		log_error("open %s failed! %s", pf, strerror(errno));
		return  -1;
	}

    log_debug("sys_network_update:\n", ip, netmask);
    while(fgets(line, sizeof(line) - 1, pf) != NULL)
    {
        if(!strncmp(line, ip_flag, strlen(ip_flag)))
            sprintf(buf+strlen(buf), "%s=%s\n", ip_flag, ip);
        else if(!strncmp(line, netmask_flag, strlen(netmask_flag)))
            sprintf(buf+strlen(buf), "%s=%s\n", netmask_flag, netmask[0]?netmask:"255.255.255.0");
        else
            strcat(buf+strlen(buf), line);
    }
    
    ftruncate(fileno(pf),0);
	rewind(pf);
    log_debug("sys_network_update:\n", buf);
    
    if (fwrite(buf, 1, strlen(buf), pf) != strlen(buf))
    {      
        log_error("sys_network_update fwrite failed %s", strerror(errno));
        fclose(pf);
        return -1;
    }

    fclose(pf);
    return 0;
}

int sys_set_network(SYS_NETWORK *network_body)
{
    IF_IPV4 *ifaddr = NULL;
    int res;

    sys_if_reload();
    if((ifaddr = sys_if_search_from_ip(g_node_ip)) == NULL)
    {
        log_warn("get ifaddr failed. ip=%s", g_node_ip);
        return -1;
    }

    if(sys_network_update(ifaddr->if_name, network_body->ipaddr, network_body->netmask))
        return -1;
    
    //ifconfig enp4s0 192.168.20.20 netmask 255.255.255.0
	if(system("systemctl restart network") != 0)
    {
        log_debug("restart network failed!");
		return -1;
	}
    
    log_debug("restart network succes!");
    //timed_task(register_backend_cb, 1, 0);
	return 0;
}

void timed_task_init(struct event_base *base)
{
    g_timed_base = base;
}

void timed_task(void (*callback)(evutil_socket_t fd, short events, void *arg), int inteval, int repeat)
{
    struct event *ev_time = event_new(NULL, -1, 0, NULL, NULL);
    struct timeval tv;
    
    if (repeat)
        event_assign(ev_time, g_timed_base, -1, EV_PERSIST, callback, (void *)&ev_time);
    else
        event_assign(ev_time, g_timed_base, -1, 0, callback, NULL);

    if (inteval == 0)
        inteval = TIME_INTEVAL;

    log_debug("time task started!");
    log_debug("evtime: %p", ev_time);
    evutil_timerclear(&tv);
    tv.tv_sec = inteval;
    event_add(ev_time, &tv);
    if (repeat)
        event_active(ev_time, EV_PERSIST, 0);
    else
        event_active(ev_time, 0, 0);

}

int node_get_db_config()
{
    int   ret = 0;
    char szErr[256];
    
    if(FC_NODE_FILE == NULL)
        return -1;
    //printf("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
        
    ret = util_conf_read(FC_NODE_FILE, "mc", "mcaddr", 
            g_mc_addr, sizeof(g_mc_addr), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        log_error( "log cfg %s", szErr);
        return -1;
    }

    ret = util_conf_read(FC_NODE_FILE, "mc", "mcport", 
            g_mc_port, sizeof(g_mc_port), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        log_error( "log cfg %s", szErr);
        return -1;
    }

    ret = util_conf_read(FC_NODE_FILE, "db", "dbaddr", 
            g_dbaddr, sizeof(g_dbaddr), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        log_error( "log cfg %s", szErr);
        return -1;
    }

    ret = util_conf_read(FC_NODE_FILE, "db", "dbport", 
            g_dbport, sizeof(g_dbport), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        log_error( "log cfg %s", szErr);
        return -1;
    }

    ret = util_conf_read(FC_NODE_FILE, "db", "dbname", 
            g_dbname, sizeof(g_dbname), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        log_error( "log cfg %s", szErr);
        return -1;
    }

    ret = util_conf_read(FC_NODE_FILE, "db", "dbuser", 
            g_dbuser, sizeof(g_dbuser), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        log_error( "log cfg %s", szErr);
        return -1;
    }

    ret = util_conf_read(FC_NODE_FILE, "db", "dbpass", 
            g_dbpass, sizeof(g_dbpass), szErr, sizeof(szErr)-1 );
    
    if (0 != ret) 
    {
        log_error( "log cfg %s", szErr);
        return -1;
    }

    return 0;
}

char *get_send_buf(int len)
{     
    if(g_send_buf_size > len)
        return g_send_buf;
        
    while(g_send_buf_size < len)
    {
        if(g_send_buf_size == 0)
            g_send_buf_size = 4096;
        else
            g_send_buf_size = g_send_buf_size*2;
    }

    free(g_send_buf);
    if((g_send_buf = (char *)malloc(g_send_buf_size)) == NULL)
    {
        log_error("g_send_buf malloc failed.");
        g_send_buf_size = 0;
    }

    return g_send_buf;
}

int node_send_msg(struct bufferevent *bev, char *buf, int len)
{
    MSG_HEADS *msg_head = (MSG_HEADS *)buf;
    int head_len = sizeof(MSG_HEADS);
    unsigned int body_en_len;

    if(get_send_buf(len+16) == NULL)
        return -1;
    
    body_en_len = g_send_buf_size-head_len;
    if(bev == NULL)
    {
        log_warn("node_send_msg send failed. msgid=%d\n", msg_head->msg_id);
        return -1;
    }

    memcpy(g_send_buf, buf, sizeof(MSG_HEADS));
    msg_head = (MSG_HEADS *)g_send_buf;
    if(SM4Encrypt(g_sm4key, buf+head_len, len-head_len, (unsigned char *)g_send_buf+head_len, &body_en_len))
    {
        log_error("SM4Encrypt failed.");
        return -1;
    }
    
    hmac_sha256(g_hmackey, sizeof(g_hmackey), (unsigned char *)g_send_buf+head_len, 
        body_en_len, msg_head->check_sum, sizeof(msg_head->check_sum));
    
    msg_head->body_len = body_en_len;
    log_trace("node_send_msg msgid=%d len=%d", msg_head->msg_id, len);
    bufferevent_write(bev, g_send_buf, head_len+body_en_len);
    bufferevent_enable(bev, EV_READ | EV_WRITE);

    return 0;
}

int node_send_auth(struct bufferevent *bev)
{
    int pkt_len = sizeof(MSG_HEADS) + sizeof(NODE_AUTH);
    char buf[1024] = {0};
    MSG_HEADS *msg_head = NULL;
    NODE_AUTH *auth = NULL;
    IF_IPV4 *ifaddr = NULL;

    if(sys_get_addr())
        return -1;

    sys_if_reload();
    if((ifaddr = sys_if_search_from_ip(g_node_ip)) == NULL)
    {
        log_warn("get ifaddr failed. ip=%s", g_node_ip);
        return -1;
    }
    
    msg_head = (MSG_HEADS *)buf;
    msg_head->msg_id = MSG_BASE_AUTH_REQ;
    msg_head->node_id = 0;
    msg_head->sn = 0;
    msg_head->body_len = sizeof(NODE_AUTH);
    
    auth = (NODE_AUTH *)(buf + sizeof(MSG_HEADS));
    //strcpy(auth->name, "firewall");
    strcpy(auth->type, NODE_TYPE_LEAKSCAN);
    strcpy(auth->ip, g_node_ip);
    strcpy(auth->mac, ifaddr->hd_addr);
    
    return node_send_msg(bev, buf, sizeof(MSG_HEADS) + sizeof(NODE_AUTH));
}

int node_send_heart(struct bufferevent *bev)
{
    char buf[1024] = {0};
    MSG_HEADS *msg_head;
    HEART_BEAT *heart_beat;
    
    msg_head = (MSG_HEADS *)buf;
    msg_head->msg_id = MSG_BASE_HEARTBEAT_REQ;
    msg_head->node_id = g_node_id;
    msg_head->sn = ++g_sn;
    msg_head->body_len = sizeof(HEART_BEAT);
    
    heart_beat = (HEART_BEAT *)(buf + sizeof(MSG_HEADS));
    sprintf(heart_beat->cpu, "%f", sys_get_cpu_rate());
    sprintf(heart_beat->mem, "%f", sys_get_mem_rate());
    sprintf(heart_beat->disk, "%f", sys_get_disk_rate());
     
    return node_send_msg(bev, buf, sizeof(MSG_HEADS) + sizeof(HEART_BEAT));
}

void node_msg_proc(struct bufferevent *bev, MSG_HEADS *msg_head, char *msg_body)
{
    char send_buf[CACHE_BUFF_SIZE+1] = {0};
    unsigned char check_sum[32+1] = {0};
    MSG_HEADS *send_msg_head = (MSG_HEADS *)send_buf;
    RSP_BODY *send_msg_body = (RSP_BODY *)(send_buf + sizeof(MSG_HEADS));
    RSP_BODY *rsp_msg_body = (RSP_BODY *)g_recv_dec_buf;
    SYS_TIME *time_body = NULL;
    int fd = -1;
    int n = 0;
    unsigned body_dec_len = MAX_RECV_BUF_SIZE;

    if(msg_head->body_len > MAX_RECV_BUF_SIZE)
    {
        log_warn("body_len=%d > MAX_RECV_BUF_SIZE(%d)", msg_head->body_len, MAX_RECV_BUF_SIZE);
        return;
    }

    if(msg_head->body_len > 0)
    {
        hmac_sha256(g_hmackey, sizeof(g_hmackey), (unsigned char *)msg_body, 
            msg_head->body_len, check_sum, sizeof(check_sum)-1);
        
        if(memcmp(msg_head->check_sum, check_sum, sizeof(check_sum)-1))
        {
            log_error("check_sum recv_check_sum=%s local_check_sum=%s", msg_head->check_sum, check_sum);
            return;
        }

        SM4Decrypt(g_sm4key, msg_body, msg_head->body_len, (unsigned char *)g_recv_dec_buf, &body_dec_len);
    }
    
    send_msg_head->node_id = g_node_id;
    g_sn = msg_head->sn;
    log_trace("---node_msg_proc msgid=%d nodeid=%d sn=%d", msg_head->msg_id, msg_head->node_id, msg_head->sn);
    switch (msg_head->msg_id)
    {
    case MSG_BASE_AUTH_RST: //认证响应包
        log_debug("node_msg_proc msgid=%d result=%s", msg_head->msg_id, rsp_msg_body->result);
        if(!strcmp(rsp_msg_body->result, MSG_RST_OK))
        {
            g_node_id = msg_head->node_id;
            g_auth = 1;
        }
        
        return;
        
    case MSG_BASE_HEARTBEAT_RST://心跳响应包
        g_sn = msg_head->sn;
        return;
/*        
    case MSG_BASE_NETWORK:
        if(sys_set_network((SYS_NETWORK *)msg_body))
            strcpy(send_msg_body->result, MSG_RST_FAILED);
        else
            strcpy(send_msg_body->result, MSG_RST_OK);
        
        break;
       
    case MSG_BASE_SET_TIME:
        time_body = (SYS_TIME *)msg_body;
        if(sys_time_set(time_body->datetime))
            strcpy(send_msg_body->result, MSG_RST_FAILED);
        else
            strcpy(send_msg_body->result, MSG_RST_OK);
        
        break;

*/         
    case MSG_BASE_SYS_REBOOT_REQ:
        strcpy(send_msg_body->result, MSG_RST_OK);
        send_msg_head->msg_id = MSG_BASE_SYS_REBOOT_RST;
        fd = bufferevent_getfd(bev);
        if (fd > 0)
        {
            n = send(fd, send_buf, sizeof(MSG_HEADS) + send_msg_head->body_len, 0);
            log_debug("send n: %d", n);
            evutil_closesocket(fd);
        }
        
        sys_reset();
        return;
 /*       
    case MSG_BASE_SYS_HALT:
        strcpy(send_msg_body->result, MSG_RST_OK);
        sys_off();
        break;
*/        
 
    default:
        return;
    }

    node_send_msg(bev, send_buf, sizeof(MSG_HEADS) + send_msg_head->body_len);

    return ;
}

static void client_read_cb(struct bufferevent *bev, void *ctx)
{
	//char buf[CACHE_BUFF_SIZE+1] = {0};
	int n=0,len = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	struct evbuffer *output = bufferevent_get_output(bev);
    MSG_HEADS *msg_head = (MSG_HEADS *)g_recv_buf;
    int head_len = sizeof(MSG_HEADS);
    static int body_len = 0;

//    len = evbuffer_get_length(input);
//	log_debug("input message len: %d", len);

    while((n = evbuffer_get_length(input)) > 0)
    {
        log_trace("evbuffer_get_length=%d  body_len=%d", n, body_len);
        // recv head
        if(body_len == 0 && n >= head_len)
        {
            if((evbuffer_remove(input, g_recv_buf, head_len)) != head_len)
            {
                log_warn("recv head len  !=  %d", head_len);
                return;
            }
            body_len = msg_head->body_len;
        }

        // recv body
        if(evbuffer_get_length(input) >= body_len)
        {
            if(body_len > MAX_RECV_BUF_SIZE)
            {
                log_warn("msg_id(%d) recv body len  >  MAX_RECV_BUF_SIZE(%d)", msg_head->msg_id, MAX_RECV_BUF_SIZE);
                return;
            }
            
            if((evbuffer_remove(input, g_recv_buf + head_len, body_len)) != body_len)
            {
                log_warn("recv body len  !=  %d", body_len);
                body_len = 0;
                return;
            }

            node_msg_proc(bev, msg_head, g_recv_buf + head_len);
            body_len = 0;
        }else
            return;

    }

    
}


static void client_event_cb(struct bufferevent *bev, short events, void *ctx)
{
	log_trace("client events: %d", events);
	if (BEV_EVENT_CONNECTED == events)
	{
		log_debug("set timeout");		
		struct timeval t={10, 0};
		bufferevent_set_timeouts(bev, &t, 0);
		bufferevent_enable(bev, EV_READ | EV_WRITE);
		g_socket_status = 1;	
		log_trace("Server connect success!");		
	}
	if (events & BEV_EVENT_ERROR)
	{
		log_error("Error from bufferevent!");
		int fd = bufferevent_getfd(bev);
		if (fd > 0)
		{
			evutil_closesocket(fd);
		}
		bufferevent_setfd(bev, -1);
		g_socket_status = 0;
        g_auth = 0;
		bufferevent_free(bev);
	}
	if (events & BEV_EVENT_EOF)
	{
		log_debug("connection is closed!");
		bufferevent_free(bev);
		g_socket_status = 0;
        g_auth = 0;
		return;
	}
	if (events & (BEV_EVENT_TIMEOUT|BEV_EVENT_READING))
	{
		log_debug("start send heart");
		node_send_heart(bev);
	}
}

struct bufferevent *socket_events_create(struct event_base *base)
{
	struct bufferevent *bev; 
	if((bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE)) == NULL)
	{
		log_error("bufferevent socket new error!");
		return NULL;
	}
	
	if (bufferevent_socket_connect(bev, (struct sockaddr*)&g_server, sizeof(g_server)) < 0)
	{
		log_error("Server connect failed!");
		bufferevent_free(bev);
		return NULL;
	}
	return bev;
}

void socket_events_set(struct bufferevent *bev)
{
	bufferevent_setcb(bev, client_read_cb, NULL, client_event_cb, NULL);
}

void socket_connect_cb(evutil_socket_t fd, short events, void *arg)
{
    static struct bufferevent *bev = NULL;
    
    log_trace("socket connect start, sock status: %d", g_socket_status);
    if(g_socket_status == 0)
    {
        if( NULL == (bev = socket_events_create(g_timed_base)))
        {
            log_error("create socket event error!");
            return;
        }
        
        socket_events_set(bev);
    }

    if(g_auth == 0 && bev != NULL)
        node_send_auth(bev);
    
}

int connect_server()
{
	struct bufferevent *bev; 	
    int port = atoi(g_mc_port);
    
	if (port <= 0 || port > 65535)
	{
		log_error("Invalid port");
		return 1;
	}

    if(g_recv_buf == NULL)
    {
        if((g_recv_buf = (char *)malloc(MAX_RECV_BUF_SIZE)) == NULL)
        {
            log_error("g_recv_buf malloc failed\n");
            return -1;
        }
    }

    if(g_recv_dec_buf == NULL)
    {
        if((g_recv_dec_buf = (char *)malloc(MAX_RECV_BUF_SIZE)) == NULL)
        {
            log_error("g_recv_dec_buf malloc failed\n");
            return -1;
        }
    }
    
    log_debug("connect_server: %s:%d", g_mc_addr, port);
	memset(&g_server, 0, sizeof(g_server));	
	g_server.sin_family = AF_INET;
	// inet_aton(host, &(g_server.sin_addr));	
	g_server.sin_port = htons(port);
	if (inet_pton(AF_INET, g_mc_addr, &g_server.sin_addr.s_addr) <= 0)
	{
		log_error("inet_pton error!");
		return 1;
	}

	g_base = event_base_new();
	if (!g_base)
	{
		log_error("Couldn't open event base");
		return 1;
	}

	timed_task_init(g_base);
    timed_task(socket_connect_cb, 10, 1);
	event_base_dispatch(g_base);
    free(g_recv_buf);
    g_recv_buf = NULL;
	return 0;
}

