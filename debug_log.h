/**************************************************************
log4c的配置文件(log4crc)需要放在可执行程序同个目录下

***************************************************************/

#ifndef __DEBUG_LOG4C_H__
#define __DEBUG_LOG4C_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "log4c.h"


#define P_TRACE     LOG4C_PRIORITY_TRACE
#define P_DEBUG     LOG4C_PRIORITY_DEBUG
#define P_WARN      LOG4C_PRIORITY_WARN
#define P_ERROR     LOG4C_PRIORITY_ERROR


#define LOG_LINE 

#define STR1(R) #R 
#define STR2(R) STR1(R)

//#define dlog(priority, ...) log4c_category_log(g_dlog, priority, "[" __FILE__ ":" STR2(__LINE__) "] " __VA_ARGS__);
#define _log_trace(...) log4c_category_log(g_dlog, LOG4C_PRIORITY_TRACE, "[" __FILE__ ":" STR2(__LINE__) "] " __VA_ARGS__);
#define _log_debug(...) log4c_category_log(g_dlog, LOG4C_PRIORITY_DEBUG, "[" __FILE__ ":" STR2(__LINE__) "] " __VA_ARGS__);
#define _log_warn(...) log4c_category_log(g_dlog, LOG4C_PRIORITY_WARN, "[" __FILE__ ":" STR2(__LINE__) "] " __VA_ARGS__);
#define _log_error(...) log4c_category_log(g_dlog, LOG4C_PRIORITY_ERROR, "[" __FILE__ ":" STR2(__LINE__) "] " __VA_ARGS__);


#define log_trace(...) _log_trace(__VA_ARGS__);
#define log_debug(...) _log_debug(__VA_ARGS__);
#define log_warn(...)  _log_warn(__VA_ARGS__);
#define log_error(...) _log_error(__VA_ARGS__);


/*

#define log_trace(...) print_log("TRACE", __VA_ARGS__)
#define log_debug(...) print_log("DEBUG", __VA_ARGS__)
#define log_warn(...)  print_log("WARN", __VA_ARGS__)
#define log_error(...) print_log("ERROR", __VA_ARGS__)
*/






void debug_log_init();
void print_log(const char *priority, const char *fmt, ...);


extern log4c_category_t* g_dlog;


#endif // __DEBUG_LOG4C_H__

