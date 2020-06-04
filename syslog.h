#ifndef _SYSLOG_H
#define _SYSLOG_H

#include <stddef.h>

namespace msyslog
{
const int LLOG_EMERG = 	0;	/* system is unusable */
const int LLOG_ALERT	= 1;	/* action must be taken immediately */
const int LLOG_CRIT	= 2;	/* critical conditions */
const int LLOG_ERR		= 3;	/* error conditions */
const int LLOG_WARNING	= 4;	/* warning conditions */
const int LLOG_NOTICE	= 5;	/* normal but significant condition */
const int LLOG_INFO	= 6;	/* informational */
const int LLOG_DEBUG	= 7;	/* debug-level messages */

int code_convert(const char *from_charset, const char *to_charset, 
                char *inbuf, size_t inlen,  
                char *outbuf, size_t outlen) ;
int u2g(char *inbuf, size_t inlen, char *outbuf, size_t outlen);
int g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen);
void yd_open_syslog();
void yd_udp_syslog(int level,
                const char *nodeid,
                const char *nodeip,
                char* tmpbuf);
void yd_close_syslog();

void ydsyslog(int level, const char *fmt, ...);



}


#endif
