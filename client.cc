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
#include <unistd.h>

#include <vector>
#include <fstream>

#include "client.h"
#include "util-pconf.h"
#include "hmac_sha2.h"
#include "sm4ende.h"
#include "syslog.h"

using namespace msyslog;

#include "easylogging++.h"

using namespace std;

IF_IPV4 *g_if_info = NULL;

struct sockaddr_in g_server;
static struct event_base *g_timed_base = NULL;
int g_socket_status = 0;
int g_auth = 0;

//节点配置
// char g_node_id[32+ 1] = {0};
int32_t  g_node_id = 0;
char g_node_ip[64] = {0};
char g_node_netmask[64] = {0};
char g_node_mac[64] = {0};
char g_node_devname[64] = {0};

//主控配置
char g_dbaddr[32] = {0};
char g_dbport[16] = {0};
char g_dbname[32] = {0};
char g_dbuser[32] = {0};
char g_dbpass[32] = {0};

char g_mc_addr[32] = {0};
char g_mc_port[16] = {0};


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


static int write_node_id(void)
{
	FILE *fp = NULL;
	char tmpbuf[256];
/*
	fp = fopen(NODE_INFO_FILE, "w+");
	if(fp == NULL)
	{
		__ulog(LLOG_ERROR, "fopen file[%s] fail!\n", NODE_INFO_FILE);
		return -1;
	}

	memset(tmpbuf, 0, sizeof(tmpbuf));
	snprintf(tmpbuf, sizeof(tmpbuf), "[waf]\nnode_id=%s\n", g_node_id);
	fwrite(tmpbuf, 1, strlen(tmpbuf), fp);
	fclose(fp);
*/
	memset(tmpbuf, 0, sizeof(tmpbuf));

	if(access(NODE_INFO_FILE, F_OK))		//文件不存在
	{
		//创建文件
		fp = fopen(NODE_INFO_FILE, "w+");
		if(fp == NULL)
		{
			LOG(ERROR) << "fopen file fail!\n";
			return -1;
		}

		memset(tmpbuf, 0, sizeof(tmpbuf));
		snprintf(tmpbuf, sizeof(tmpbuf), "[waf]\nnode_id=%d\n", g_node_id);
		fwrite(tmpbuf, 1, strlen(tmpbuf), fp);

		fclose(fp);
	}
	else
	{
		//删除
		snprintf(tmpbuf, sizeof(tmpbuf), "sed -i '/node_id.*/d' %s", NODE_INFO_FILE);
		system(tmpbuf);
		//添加
		snprintf(tmpbuf, sizeof(tmpbuf), "sed -i '$a\\node_id=%d' %s", g_node_id, NODE_INFO_FILE);
		system(tmpbuf);
	}

	return 0;
}

int checkprogramisrun(const char *pName)
{
	char sCommand[1024], sTemp[1024];
	char *p = NULL, *q = NULL;
	char sProgramName[32];
	FILE *fp=NULL;
	char *res = NULL;
	char sPidBuf[16];
	int iPid = -1;
	int i = 0;
	
	if(pName == NULL)
	{
		LOG(ERROR) <<"input parameter is null";
		return -1;
	}
#if 0
	//匹配自身进程ID，查看执行的文件名称
	memset(sCommand, 0x00, sizeof(sCommand));
	snprintf(sCommand, sizeof(sCommand)-1, "ps -ef|grep  %d|grep -v admin|grep -v grep|grep -v su|grep -v tail|grep -v vi|awk {'print $8'}|tr -d '\n'",
		getpid());
	
	memset(sTemp, 0x00, sizeof(sTemp));
	if(NULL == (fp = popen(sCommand, "r")))
	{
		__ulog(LLOG_ERROR, "popen(%s) errno[%s].\n", sCommand, strerror(errno));
		pclose(fp);
		return -1;
	}
	else
		{				
			fgets(sTemp, sizeof(sTemp)-1, fp);  
			if(sTemp[0] == '\0')
			{
				__ulog(LLOG_ERROR, "exec[%s] ret null.\n", sCommand);
				pclose(fp);
				return -1;
			}	

			//如果是完整路径执行的则取得最后文件进程名称
			if((p = strrchr(sTemp, '/')) == NULL)
				strncpy(sProgramName, sTemp, sizeof(sProgramName)-1);
			else
				strncpy(sProgramName, p+1, sizeof(sProgramName)-1);
		}
	
	pclose(fp);

	//如果自身的名字不是传入进来的名称说明文件名称被修改了
	if(strcmp(sProgramName, pName) != 0)   
	{
		__ulog(LLOG_ERROR, "you run program[%s] is illegal.\n", sProgramName);
		return -1;
	}
#endif
	//不匹配自身的进程有没有其他进程在运行
	memset(sCommand, 0x00, sizeof(sCommand));
	snprintf(sCommand, sizeof(sCommand)-1, "ps -ef|grep -v %d|grep \"%s\"|grep -v admin|grep -v grep|grep -v su|grep -v tail|grep -v vi|awk {'print $2\"||\"$8'}|tr -d '\n'",
		getpid(), pName);

	LOG(INFO) << sCommand;
	memset(sTemp, 0x00, sizeof(sTemp));
	if(NULL == (fp = popen(sCommand, "r")))
	{
		LOG(ERROR) <<  sCommand << strerror(errno);
		pclose(fp);
		return -1;
	}
	else
		{				
			fgets(sTemp, sizeof(sTemp)-1, fp);  
			if(sTemp[0] == '\0')
			{
				//fprintf(stderr, "exec[%s] ret null.\n", sCommand);
				pclose(fp);
				return 0;
			}	
			
			memset(sPidBuf, 0, sizeof(sPidBuf));

			p = NULL;
			res = strtok_r(sTemp, "||", &p);
			while(res != NULL)
			{
				if(i == 0)
				{
					strncpy(sPidBuf, res, sizeof(sPidBuf));
					iPid = atoi(sPidBuf);
				}
				else if(i == 1)
				{
					if((q = strrchr(res, '/')) == NULL)
						strncpy(sProgramName, res, sizeof(sProgramName)-1);
					else
						strncpy(sProgramName, q+1, sizeof(sProgramName)-1);
				}

				i++;
				res = strtok_r(NULL, "||", &p);
			}
		
		}
	
	pclose(fp);

	if(strcmp(sProgramName, pName) == 0)
	{
		LOG(INFO) << "you run programs is already runing.";
		return iPid;
	}

	
	return 0;
}


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
            LOG(ERROR) << "malloc";
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
    // IF_IPV4 *p = NULL;
    // int family;  /* protocl family */

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
#if 1	
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
		LOG(ERROR) << "connect error";
		close(sockSend);
		return -1;
	}

    //getpeername(sockSend, (struct sockaddr *)&addSend, &n);
    getsockname(sockSend, (struct sockaddr *)&addSend, &n);
    strcpy(g_node_ip, inet_ntoa(addSend.sin_addr));
    LOG(INFO) << "g_node_ip=" <<  g_node_ip;
    close(sockSend);
#endif
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
    //__ulog(LLOG_INFO, "time1: %ld %ld %ld %ld %ld %ld %ld\n", time1.user, time1.nice, time1.system, time1.idle, time1.irq, time1.softirq, time1.guest);
    //__ulog(LLOG_INFO, "time2: %ld %ld %ld %ld %ld %ld %ld\n", time2.user, time2.nice, time2.system, time2.idle, time2.irq, time2.softirq, time2.guest);
    //__ulog(LLOG_INFO, "cpu total: %ld\n", total);
    //__ulog(LLOG_INFO, "cpu idle: %ld\n", idle);
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
        //printf("current total size: %llu, use size: %llu", dev_total, dev_use);
    }
    pclose(disk);
    rate = ((double)use / (double)total) * 100; 
	LOG(INFO) << "current disk rate:" << rate << " " <<  use << " " << total;  
    
    return rate;
}


int sys_time_set(char *datetime)
{
	struct timeval tv;


	tv.tv_sec = atoi(datetime);
	tv.tv_usec = 0;
	if(settimeofday(&tv, NULL) < 0)
	{
		LOG(ERROR) << "sys_time_set failed";
		return -1;
	}

    system("hwclock -w");

	return 0;
}

void sys_reset()
{
    LOG(INFO) << "reboot started!";
    system("reboot");
}

void sys_off()
{
    LOG(INFO) << "poweroff started!";
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
		//__ulog(LLOG_ERROR, "open %s failed! %s\n", if_file, strerror(errno));
		return  -1;
	}

    while(fgets(line, sizeof(line) - 1, pf) == NULL)
    {
        if(!strncmp(line, ip_flag, strlen(ip_flag)))
            sprintf(buf+strlen(buf), "%s=%s\n", ip_flag, ip);
        else if(!strncmp(line, netmask_flag, strlen(netmask_flag)))
            sprintf(buf+strlen(buf), "%s=%s\n", netmask_flag, netmask);
        else
            strcat(buf+strlen(buf), line);
    }
    
    ftruncate(fileno(pf),0);
	rewind(pf);
    if (fwrite(buf, 1, strlen(buf), pf) != strlen(buf))
    {      
        //__ulog(LLOG_ERROR, "sys_network_update fwrite failed %s\n", strerror(errno));
        fclose(pf);
        return -1;
    }

    fclose(pf);
    return 0;
}

int sys_set_network(SYS_NETWORK *network_body)
{
    IF_IPV4 *ifaddr = NULL;
    // int res;

    sys_if_reload();
    if((ifaddr = sys_if_search_from_ip(g_node_ip)) == NULL)
    {
        //__ulog(LLOG_ERROR, "get ifaddr failed. ip=%s\n", g_node_ip);
        return -1;
    }

    if(sys_network_update(ifaddr->if_name, network_body->ipaddr, network_body->netmask))
        return -1;
    
	if(system("systemctl restart network") != 0)
    {
        //__ulog(LLOG_ERROR, "restart network failed!\n");
		return -1;
	}
    
    //__ulog(LLOG_INFO, "restart network succes!\n");
    //timed_task(register_backend_cb, 1, 0);
	return 0;
}

void power_reset_cb(evutil_socket_t fd, short events, void *arg)
{
	system("reboot");
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

    LOG(INFO) << "time task started!";
    LOG(INFO) << "evtime: " <<  ev_time;
    
    evutil_timerclear(&tv);
    tv.tv_sec = inteval;
    event_add(ev_time, &tv);
    if (repeat)
        event_active(ev_time, EV_PERSIST, 0);
    else
        event_active(ev_time, 0, 0);

}

int node_get_db_config(void)
{
    int   ret = 0;
    char szErr[256];
    
    if(WAF_CFG_NAME == NULL)
        return -1;
    //printf("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
        
    ret = util_conf_read(WAF_CFG_NAME, "mc", "mcaddr", 
            g_mc_addr, sizeof(g_mc_addr), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        LOG(ERROR) << "get mcaddr from log cfg fail! ";
        return -1;
    }

    ret = util_conf_read(WAF_CFG_NAME, "mc", "mcport", 
            g_mc_port, sizeof(g_mc_port), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        LOG(ERROR) << "get mcaddr from log cfg fail! ";
        return -1;
    }

    ret = util_conf_read(WAF_CFG_NAME, "db", "dbaddr", 
            g_dbaddr, sizeof(g_dbaddr), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        LOG(ERROR) << "get mcaddr from log cfg fail! ";
        return -1;
    }

    ret = util_conf_read(WAF_CFG_NAME, "db", "dbport", 
            g_dbport, sizeof(g_dbport), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        LOG(ERROR) << "get mcaddr from log cfg fail! ";
        return -1;
    }

    ret = util_conf_read(WAF_CFG_NAME, "db", "dbname", 
            g_dbname, sizeof(g_dbname), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        LOG(ERROR) << "get mcaddr from log cfg fail! ";
        return -1;
    }

    ret = util_conf_read(WAF_CFG_NAME, "db", "dbuser", 
            g_dbuser, sizeof(g_dbuser), szErr, sizeof(szErr)-1 );
    if (0 != ret) 
    {
        LOG(ERROR) << "get mcaddr from log cfg fail! ";
        return -1;
    }

    ret = util_conf_read(WAF_CFG_NAME, "db", "dbpass", 
            g_dbpass, sizeof(g_dbpass), szErr, sizeof(szErr)-1 );
    
    if (0 != ret) 
    {
        LOG(ERROR) << "get mcaddr from log cfg fail! ";
        return -1;
    }

    return 0;
}

int node_send_msg(struct bufferevent *bev, char *buf, size_t len)
{
    if (!bev || !buf)
    {
        LOG(ERROR) << "!bev || !buf";
        return -1;
    }
    if (len < sizeof(MSG_HEADS))
    {
        LOG(ERROR) << "len < head len";
        return -1;
    }
    MSG_HEADS *msg_head = (MSG_HEADS *)buf;
    size_t headlen = sizeof(MSG_HEADS);
    int bodylen = msg_head->len;
    char *pbody = buf + headlen;

    unsigned int outlen = bodylen * 2;
    // calloc
    unsigned char * outbuf = (unsigned char *)calloc(outlen, 1);
    if (!outbuf)
    {
        LOG(ERROR) << "calloc error";
        return -1;
    }
    // SM4 encrypt
    if (SM4Encrypt(g_sm4key, pbody, bodylen, outbuf, &outlen))
    {
        LOG(ERROR) << "SM4 encrypt error";
        free(outbuf);
        return -1;
    }
    // HMAC
    hmac_sha256(g_hmackey, sizeof(g_hmackey), outbuf, outlen, 
                msg_head->check_sum, sizeof(msg_head->check_sum));
    msg_head->len = outlen;

	LOG(INFO) << "node_send_msg msgid=" << msg_head->msgid 
		<< " msg=" << msgid2str(msg_head->msgid) << " total len=" <<  headlen + outlen;
    bufferevent_write(bev, buf, headlen); // head
    bufferevent_write(bev, outbuf, outlen); // encrypted body
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    free(outbuf);
    return 0;

}

int node_send_auth(struct bufferevent *bev)
{
    // int pkt_len = sizeof(MSG_HEADS) + sizeof(NODE_AUTH);
    char buf[1024] = {0};
    MSG_HEADS *msg_head = NULL;
    NODE_AUTH *auth = NULL;
    IF_IPV4 *ifaddr = NULL;

    if(sys_get_addr())
        return -1;

    sys_if_reload();
    if((ifaddr = sys_if_search_from_ip(g_node_ip)) == NULL)
    {
        LOG(ERROR) << "get ifaddr failed";
        return -1;
    }
    
    msg_head = (MSG_HEADS *)buf;
    msg_head->len = sizeof(NODE_AUTH);
    msg_head->msgid = MSG_BASE_AUTH_REQ;

    sys_if_reload();
    sys_if_search_from_ip(g_node_ip);
    auth = (NODE_AUTH *)(buf + sizeof(MSG_HEADS));
    // strcpy(auth->name, "WAF");
    strcpy(auth->type, NODE_TYPE);
    strcpy(auth->ip, g_node_ip);
    strcpy(auth->mac, ifaddr->hd_addr);
    
    return node_send_msg(bev, buf, sizeof(MSG_HEADS) + sizeof(NODE_AUTH));
}

int node_send_heart(struct bufferevent *bev)
{
    // int pkt_len = sizeof(MSG_HEADS) + sizeof(HEART_BEAT);
    char buf[1024] = {0};
    MSG_HEADS *msg_head;
    HEART_BEAT *heart_beat;

    
    msg_head = (MSG_HEADS *)buf;
    msg_head->len = sizeof(HEART_BEAT);
    msg_head->msgid = MSG_BASE_HEARTBEAT_REQ;
    
    heart_beat = (HEART_BEAT *)(buf + sizeof(MSG_HEADS));
    // strncpy(heart_beat->id, g_node_id, sizeof(heart_beat->id)-1);
    sprintf(heart_beat->cpu, "%f", sys_get_cpu_rate());
    sprintf(heart_beat->mem, "%f", sys_get_mem_rate());
    sprintf(heart_beat->disk, "%f", sys_get_disk_rate());
    node_send_msg(bev, buf, sizeof(MSG_HEADS) + sizeof(HEART_BEAT));
        
    return 0;
}

void node_msg_proc(struct bufferevent *bev, MSG_HEADS *msg_head, char *msg_body)
{
	int ret;
	char cmd[256];
    MSG_HEADS head;
    RSP_BODY body;
    RSP_BODY * rsp_body = NULL;
    bzero(&head, sizeof(head));
    bzero(&body, sizeof(body));
    unsigned char enbody[512] = {0};
    int enbody_len = 0;
    // int bodylen = msg_head->len;

    int fd = -1;
    int n = 0;
    // int nums = 0;
	
    LOG(INFO) << "node_msg_proc msgid=" <<  msg_head->msgid 
		<< " msg=" << msgid2str(msg_head->msgid) << " totallen=" <<  msg_head->node_id;
    if (!msgid2str(msg_head->msgid))
    {
        LOG(ERROR) << "Unknow msg id";
        ydsyslog(LLOG_INFO, "%s", "Unknow msg id!");
        return;
    }

    switch (msg_head->msgid)
    {
    case MSG_BASE_AUTH_RST: //认证响应
        rsp_body = (RSP_BODY*)msg_body;
        // strncpy(g_node_id, rsp_msg_body->id, sizeof(g_node_id)-1);
        LOG(INFO) << " node_id=" << g_node_id << " result=" << rsp_body->result; 
        if(!strcmp(rsp_body->result, MSG_RST_OK))
        {
            g_node_id = msg_head->node_id;
            g_auth = 1;
        }

		//节点id写入文件
		ret = write_node_id();
		if(ret != 0)
		{
			LOG(ERROR) << "write_node_id to file fail!";
			// return;
		}
        return;
        
    case MSG_BASE_HEARTBEAT_RST://心跳
        return;
        
    // case MSG_BASE_NETWORK:
    //     if(sys_set_network((SYS_NETWORK *)msg_body))
    //         strcpy(send_msg_body->result, MSG_RST_FAILED);
    //     else
    //         strcpy(send_msg_body->result, MSG_RST_OK);
        
    //     break;
        
    // case MSG_BASE_SET_TIME:
    //     time_body = (SYS_TIME *)msg_body;
    //     if(sys_time_set(time_body->datetime))
    //         strcpy(send_msg_body->result, MSG_RST_FAILED);
    //     else
    //         strcpy(send_msg_body->result, MSG_RST_OK);
        
    //     break;
        
    case MSG_BASE_SYS_REBOOT_REQ:

        enbody_len = sizeof(enbody);
        strcpy(body.result, MSG_RST_OK);
        head.msgid = MSG_BASE_SYS_REBOOT_RST;
        // encrypt
        SM4Encrypt(g_sm4key, (char*)&body, sizeof(body), enbody, (unsigned int*)&enbody_len);
        head.len = enbody_len;
        // hmac
        hmac_sha256(g_hmackey, sizeof(g_hmackey), (unsigned char*)&enbody, enbody_len,
                    head.check_sum, sizeof(head.check_sum));

        ydsyslog(LLOG_INFO, "%s", "Reboot!");

        fd = bufferevent_getfd(bev);
		if (fd > 0)
		{
            n = send(fd, &head, sizeof(MSG_HEADS), 0);
            LOG(INFO) << "send head n: " <<  n;
            n = send(fd, &enbody, enbody_len, 0);
            LOG(INFO) << "send body n:" <<  n;
            evutil_closesocket(fd);
            bufferevent_setfd(bev, -1);
		}
        // log_debug("close socket");
        sleep(5);
        timed_task(power_reset_cb, 1, 0);
        return;
        
    // case MSG_BASE_SYS_HALT:
    //     strcpy(send_msg_body->result, MSG_RST_OK);
    //     node_send_msg(bev, send_buf, sizeof(MSG_HEADS) + send_msg_head->len);
    //     sys_off();
    //     break;
	
    default:
        return;
    }
    bzero(cmd, sizeof(cmd));
    memcpy(cmd, &head, sizeof(head));
    memcpy(cmd + sizeof(head), &body, sizeof(body));
    node_send_msg(bev, cmd, sizeof(head) + sizeof(body));

    return ;
}

int checkHMAC(char* msg, size_t msglen)
{
    if (msglen < sizeof(MSG_HEADS))
    {
        return -1;
    }
    MSG_HEADS* phead = (MSG_HEADS*)msg;
    char* pbody = msg + sizeof(MSG_HEADS);
    int bodylen = phead->len;
    if (bodylen == 0)
    {
        //no body
        return 0;
    }
    unsigned char mac[32] = {0};
    hmac_sha256(g_hmackey, sizeof(g_hmackey), (unsigned char*)pbody, bodylen, mac, 
                sizeof(mac));
    if (memcmp(phead->check_sum, mac, sizeof(mac)))
    {
        return -1;
    }
    return 0;
}

static void client_read_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	// struct evbuffer *output = bufferevent_get_output(bev);
    MSG_HEADS *msg_head = NULL;
    size_t headlen = sizeof(MSG_HEADS);
    char* headbuf = NULL;
    if (!(headbuf = (char*)calloc(headlen, 1)))
    {
        LOG(ERROR) << "calloc error";
        return;
    }

	LOG(INFO) << "input message len:" <<  evbuffer_get_length(input);

    while (evbuffer_get_length(input) >= headlen)
    {
        bzero(headbuf, headlen);
        evbuffer_copyout(input, headbuf, headlen);
        msg_head = (MSG_HEADS *)headbuf;
        size_t msglen = headlen + msg_head->len;
        if (msglen > 65535 || msglen < 0) 
        {
            LOG(ERROR) << "Invalid message length:" << msglen;
            free(headbuf);
            return;
        }else if (evbuffer_get_length(input) >= msglen){
            // a message
            char* msg = (char*)calloc(msglen, 1);
            if (!msg)
            {
                LOG(ERROR) << "calloc error";
                free(headbuf);
                return;
            }
            evbuffer_remove(input, msg, msglen);
            // check HMAC of a msg
            if (checkHMAC(msg, msglen))
            {
                LOG(ERROR) << "HMAC not match";
                free(msg);
                // free(headbuf);
                continue;
            }
            // decrypt
            int outlen = msg_head->len + 64;
            unsigned char* pdebody = (unsigned char*)calloc(outlen, 1);
            if (!pdebody)
            {
                LOG(ERROR) << "calloc error";
                free(msg);
                free(headbuf);
                return;
            }
            SM4Decrypt(g_sm4key, msg + headlen, msg_head->len, 
                        pdebody, (unsigned int*)&outlen);
            ((MSG_HEADS*)msg)->len = outlen;
            node_msg_proc(bev, (MSG_HEADS*)msg, (char*)pdebody);
            free(msg);
            free(pdebody);
            // free(headbuf);
        }else{
            break;
        }
    }
    free(headbuf);   
}

static void client_event_cb(struct bufferevent *bev, short events, void *ctx)
{
	LOG(INFO) << "client events: " <<  events;
	if (BEV_EVENT_CONNECTED == events)
	{
		//printf("set timeout");		
		struct timeval t={10, 0};
		bufferevent_set_timeouts(bev, &t, 0);
		bufferevent_enable(bev, EV_READ | EV_WRITE);
		g_socket_status = 1;	
		LOG(INFO) << "Server connect success!";
        ydsyslog(LLOG_INFO, "%s", "Server connect success!");
	}
	if (events & BEV_EVENT_ERROR)
	{
		LOG(ERROR) << "Error from bufferevent!";
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
		LOG(INFO) << "connection is closed!";
		bufferevent_free(bev);
		g_socket_status = 0;
		g_auth = 0;
		return;
	}
	if (events & (BEV_EVENT_TIMEOUT|BEV_EVENT_READING))
	{
		LOG(INFO) << "start send heart";
		node_send_heart(bev);
	}
}

struct bufferevent *socket_events_create(struct event_base *base)
{
	struct bufferevent *bev; 
	if((bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE)) == NULL)
	{
		LOG(ERROR) << "bufferevent socket new error!";
		return NULL;
	}
	
	if (bufferevent_socket_connect(bev, (struct sockaddr*)&g_server, sizeof(g_server)) < 0)
	{
		LOG(ERROR) << "Server connect failed!";
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
    
    LOG(INFO) << "socket connect start, sock status: " << g_socket_status;
    if(g_socket_status == 0)
    {
        if( NULL == (bev = socket_events_create(g_timed_base)))
        {
            LOG(ERROR) << "create socket event error!";
            return;
        }
        
        socket_events_set(bev);
    }

    if(g_auth == 0 && bev != NULL)
        node_send_auth(bev);
    
}

int connect_server(void)
{
	struct event_base *base;
	// struct bufferevent *bev; 	
    int port = atoi(g_mc_port);
    
	if (port <= 0 || port > 65535)
	{
		LOG(ERROR) << "Invalid port";
		return 1;
	}

	memset(&g_server, 0, sizeof(g_server));	
	g_server.sin_family = AF_INET;
	// inet_aton(host, &(g_server.sin_addr));	
	g_server.sin_port = htons(port);
	if (inet_pton(AF_INET, g_mc_addr, &g_server.sin_addr.s_addr) <= 0)
	{
		LOG(ERROR) << "inet_pton error!";
		return 1;
	}

	base = event_base_new();
	if (!base)
	{
		LOG(ERROR) << "Couldn't open event base";
		return 1;
	}

	timed_task_init(base);
    timed_task(socket_connect_cb, 10, 1);
	event_base_dispatch(base);
	return 0;
}

const char* msgid2str(int32_t msgid)
{
    switch (msgid)
    {
		case MSG_BASE_REGISTRE_REQ:         
			return "节点注册请求" ;
		case MSG_BASE_REGISTRE_RST:         
			return "节点注册响应" ;
		case MSG_BASE_AUTH_REQ:             
			return "节点认证请求" ;
		case MSG_BASE_AUTH_RST:             
			return "节点认证响应" ;
		case MSG_BASE_HEARTBEAT_REQ:        
			return "心跳请求" ;
		case MSG_BASE_HEARTBEAT_RST:        
			return "心跳响应" ;
		case MSG_BASE_SYS_REBOOT_REQ:       
			return "设备重启请求" ;
		case MSG_BASE_SYS_REBOOT_RST:       
			return "设备重启响应" ;
    }
    return NULL;
}
