#ifndef _UTIL_CONF_H
#define _UTIL_CONF_H

#ifdef  __cplusplus
extern "C"{
#endif

int util_conf_read(const char *pfile,
                  const char *psSectionName,
                  const char *psItemName,
                        char *psItemVal,
                        int   valLen,
                        char *psErrMsg,
                        int   iErrLen
                 );



#ifdef  __cplusplus
}
#endif

#endif