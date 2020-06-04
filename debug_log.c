#include <time.h>
#include <stdio.h>
#include "debug_log.h"



log4c_category_t* g_dlog = NULL;


/*获取当前时间格式"2009-3-31 10:43:49" 
#include <time.h> */
char *get_cur_time(char *time_buf)
{
    time_t t;
    struct tm *tp;

    t=time(NULL);
    tp=localtime(&t);

	sprintf(time_buf, "%d-%02d-%02d %02d:%02d:%02d",
            tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,
            tp->tm_hour,tp->tm_min,tp->tm_sec);
	
	return time_buf;
}


void debug_log_init()
{

    if (log4c_init())
      printf("log4c_init() failed\n");
    else
        g_dlog = log4c_category_get("fc-leakscan");
    
}

void print_log(const char *priority, const char *fmt, ...)
{
    char cur_time[32] = {0};
	va_list ap;

	fprintf(stderr, "%s %s [%s:%d]", get_cur_time(cur_time), priority, __FILE__, __LINE__ );
	va_start(ap,fmt);
	vfprintf(stderr,fmt,ap);
	va_end(ap);
    fprintf(stderr, "\n");
}


