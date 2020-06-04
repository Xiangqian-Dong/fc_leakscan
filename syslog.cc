#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <stdbool.h>
#include <stdlib.h>
#include<sys/time.h>
#include<ctype.h>
#include<netinet/tcp.h>
#include<signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <iconv.h>  
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <sys/syslog.h>
#include "syslog.h"

const char* g_nodeid = "waf";
const char* g_nodeip = "192.168.20.99";
//全局变量
// int opensyslog = 1;  //开关

using namespace msyslog;
//转码部分
int msyslog::code_convert(const char *from_charset, 
				const char *to_charset, 
				char *inbuf, 
				size_t inlen,  
				char *outbuf, 
				size_t outlen) 
 {  
    iconv_t cd;  
    char **pin = &inbuf;  
    char **pout = &outbuf;  
    cd = iconv_open(to_charset, from_charset);  
    if (cd == 0)  
        return -1;  

    memset(outbuf, 0, outlen);  

    if (iconv(cd, pin, &inlen, pout, &outlen) == (size_t)-1)  
    	{
       	 return -1; 
    	}

    iconv_close(cd);  
    *pout = '\0';  
  
    return 0;  
}  
  
int msyslog::u2g(char *inbuf, size_t inlen, char *outbuf, size_t outlen) {  
	return code_convert("utf-8", "gb2312", inbuf, inlen, outbuf, outlen);  
}  
  
int msyslog::g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen) {  
	return code_convert("gb2312", "utf-8", inbuf, inlen, outbuf, outlen);  
}  

void msyslog::ydsyslog(int level, const char *fmt, ...)
{	
    char tmpbuf[6024] = {0};
	char* p = tmpbuf;
    va_list args;
	va_start(args, fmt);
	vsnprintf(tmpbuf, sizeof(tmpbuf)-1, fmt, args);
	va_end(args);
    yd_udp_syslog(level, g_nodeid, g_nodeip, p); 
}

void msyslog::yd_open_syslog()
{
	//打开日志设备
	::openlog("ydlog",LOG_CONS | LOG_PID,0);

}

// void yd_udp_syslog(int level,char *nodeid,char *nodeip,const char *fmt, ...)
void msyslog::yd_udp_syslog(int level, const char *nodeid, const char *nodeip, char *tmpbuf)
{
	char logbuf[8000]; 
	// outbuf[8000];
	// int outlen = sizeof(outbuf);
	// char tmpbuf[6024];
	char level_chn[128];

	struct timeval tv;
	struct tm *ptm;
	char sNowTime[256];


//取系统时间
	srand(time(NULL));
	gettimeofday(&tv, NULL);
	ptm = localtime(&tv.tv_sec);
	memset(sNowTime, 0x00, sizeof(sNowTime));
	snprintf(sNowTime, sizeof(sNowTime),
			"%04d-%02d-%02d %02d:%02d:%02d",
			ptm->tm_year + 1900,
			ptm->tm_mon + 1,
			ptm->tm_mday,
			ptm->tm_hour,
			ptm->tm_min,
			ptm->tm_sec);
			

	//写入日志
	memset(logbuf,0,sizeof(logbuf));
	// memset(tmpbuf,0,sizeof(tmpbuf));
	memset(level_chn,0,sizeof(level_chn));

	// va_list args;
	// va_start(args, fmt);
	// vsnprintf(tmpbuf, sizeof(tmpbuf)-1, fmt, args);
	// va_end(args);

	switch(level)
	{
		case LLOG_EMERG:
		snprintf(level_chn,sizeof(level_chn),"系统不可用");
		break;
		
		case LLOG_ALERT:
		snprintf(level_chn,sizeof(level_chn),"紧急");
		break;	

		case LLOG_CRIT:
		snprintf(level_chn,sizeof(level_chn),"重要情况");
		break;
		case LLOG_ERR:
		snprintf(level_chn,sizeof(level_chn),"错误");
		break;

		case LLOG_WARNING:
		snprintf(level_chn,sizeof(level_chn),"告警");
		break;
		
		case LLOG_NOTICE:
		snprintf(level_chn,sizeof(level_chn),"注意");
		break;		

		case LLOG_INFO:
		snprintf(level_chn,sizeof(level_chn),"通知");
		break;	

		case LLOG_DEBUG:
		snprintf(level_chn,sizeof(level_chn),"调试");
		break;	

		default:
			return;
	}


	snprintf(logbuf,sizeof(logbuf),"来自设备:防火云-[%s]-[%s]|时间:%s|信息等级:%s|详情:%s",nodeid,nodeip,sNowTime,level_chn,tmpbuf);
	printf("logbuf=%s\n", logbuf);
	//转码
	// memset(outbuf,0,sizeof(outbuf));
	// outlen = sizeof(outbuf);
	// if(strlen(logbuf) > 0)
	// 	g2u(logbuf,strlen(logbuf),outbuf,outlen);

	// syslog(level,outbuf);
	::syslog(level, logbuf);

}

void msyslog::yd_close_syslog()
{
	//关闭日志设备
	::closelog();

}

#if 0
#define ydsyslog(level, f, a...) \
do { \
  	if (opensyslog==1)\
  	{\
		yd_udp_syslog(level,nodeid,nodeip,f, ##a); \
	}\
	else\
	{\
		break; \
	}\
} while (0) 
#endif

// int main(int argc, char **argv)
// {
// 	char test[]="12345678";
	
// 	yd_open_syslog();
	
// 	ydsyslog(LOG_INFO,"我们是共产主义接班人![%s]",test);

// 	yd_close_syslog();

// 	return 0;	
// }
