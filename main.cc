#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>

#include "client.h"
#include "syslog.h"

#include "easylogging++.h"

INITIALIZE_EASYLOGGINGPP

#define  FC_WAF_VER			"WAF 1.0.4.24"


extern char g_dbaddr[32];
extern char g_dbport[16];
extern char g_dbname[32];
extern char g_dbuser[32];
extern char g_dbpass[32];

extern char g_mc_addr[32];
extern char g_mc_port[16];

static unsigned int idx;

void rolloutHandler(const char* filename, std::size_t size) {
   // SHOULD NOT LOG ANYTHING HERE BECAUSE LOG FILE IS CLOSED!
   std::cout << "************** Rolling out [" << filename << "] because it reached [" << size << " bytes]" << std::endl;

   // BACK IT UP
   std::stringstream ss;
   ss << "mv " << filename << " " << filename << "." << ++idx;
   system(ss.str().c_str());
}

int main(int argc, char **argv)
{
	// int ret;
	idx = 0;
	int c;
	// int db_port = -1;
	// int main_port = -1;
	// char cmd[256];
	int dae = 0;
	
	
	while(1)	
	{		
		static struct option long_options[]=		
		{			
			{"version",0,0,'v'},
			{"daemon",0,0,'d'},
			{0,0,0,0}
		};

		c = getopt_long(argc,argv,"vd",long_options,NULL);
		if (c == -1)
		{			
			break;		
		}		

		switch(c)
		{
			case 'v':
				printf("version: %s\n", FC_WAF_VER);
				return 0;

			case 'd':
				dae = 1;
		    	break;

			default:
				return -1;			
		}
	}

	if (dae)
	{
		daemon(1, 0);
	}

	el::Loggers::addFlag(el::LoggingFlag::StrictLogFileSizeCheck);
	el::Loggers::reconfigureAllLoggers(el::ConfigurationType::Filename, FC_LOG_FILE);
	el::Loggers::reconfigureAllLoggers(el::ConfigurationType::MaxLogFileSize, "10000000");
    el::Loggers::reconfigureAllLoggers(el::ConfigurationType::Format, 
										"%datetime-%level-%fbase:%line : %msg");
	el::Helpers::installPreRollOutCallback(rolloutHandler);

	//读取主控配置
	if(node_get_db_config())
	{
		// __ulog(LLOG_ERROR, "node_get_db_config from %s fail!\n", WAF_CFG_NAME);
		LOG(ERROR) << "node_get_db_config from error";
		return -1;
	}

	msyslog::yd_open_syslog();
	//连接主控
	//main_port = atoi(g_mc_port);
	connect_server();




	return 0;
}
