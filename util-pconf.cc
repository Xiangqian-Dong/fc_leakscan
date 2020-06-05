#ifdef  __cplusplus
extern "C"{
#endif


#include "util-pconf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>


// 去除字串末尾空格
char *str_rtrim (char *s)
{
    register char *p;

    //TRACE0;
    //ASSERT (s != NULL);

    p = s + strlen (s);
    if (p > s)
    {
        do { --p; } while (isspace (*p));
        p[1] = '\0';
    }
    return s;
}

// 去除字串前面空格
char *str_ltrim (char *s)
{
    register char *p, *q;;

    //TRACE0;
    //ASSERT (s != NULL);

    p = q = s;
    while (isspace (*q))
        ++q;
    while (*q)
        *p++ = *q++;
    *p = '\0';
    return s;
}


/*******************************************************
 * 函数名称  : read
 * 描    述  : 读取配置文件
 * 输入参数  : const char *psSectionName 段名
 *             const char *psItemName    项名
 *             const int iErrLen         错误信息缓冲区长度
 * 输出参数  : char *psItemVal           项值
 *             char *psErrMsg            错误信息
 * 返回值    : 0 成功 -1 失败
 *******************************************************/
int util_conf_read(const char *pfile,
                  const char *psSectionName,
                  const char *psItemName,
                        char *psItemVal,
                        int   valLen,
                        char *psErrMsg,
                        int   iErrLen
                 )
{
    FILE *fp = NULL;
    int  iLine = 0;
    char sLine[256+1];
    int  iSecFoundFlg = 0;


    //参数合法性检查
    if ( !psSectionName || !psItemName || !psItemVal || valLen <= 0 || iErrLen <= 0)
    {
        return -1;
    }

    if (NULL == (fp = fopen(pfile, "rb")))
    {
        snprintf( psErrMsg, iErrLen, "fopen(%s) %d:%s", pfile, errno, strerror(errno) );
        return -2;
    }

    rewind(fp);

    //memset(sLine, 0U, sizeof(sLine));

    while (fgets(sLine, sizeof(sLine), fp) != NULL)
    {
        sLine[sizeof(sLine)-1]='\0';

        char *ptr = sLine;
        //added by power
        if (NULL == strrchr(sLine, '\n')) {
            //line is too long
            continue;
        }
        //记录行数
        iLine ++;

        while(isspace(*ptr)) { ptr++ ; }

        if ( (*ptr) == '\0' || (*ptr) == '#' || (*ptr) == '\n' || ((*ptr)=='/' && *(ptr+1)=='/') || (*ptr) != '[')
        {
            continue;
        }
        else
        {
            ptr++;
            char sBuf[64];
            unsigned int i = 0;
            //memset(sBuf, 0, sizeof(sBuf));
            //取得配置段名称
            while ((*ptr != ']') && (*ptr != ' ') && (i<sizeof(sBuf)-1))
            {
                sBuf[i] = *ptr;
                ptr++; i++;
            }
            sBuf[i]='\0';

            //是要找的配置段 - modified by power
            if (strcmp(sBuf, psSectionName) == 0)
            {
                iSecFoundFlg = 1;

                int iItemFoundFlg = 0;
                //memset(sLine, 0U, sizeof(sLine));
                while (fgets(sLine, sizeof(sLine), fp) != NULL)
                {
                    sLine[sizeof(sLine)-1]='\0';
                    iLine ++;

                    ptr = sLine;

                    while(isspace(*ptr)) { ptr++ ; }

                    //if ((*ptr == '#') || (memcmp(ptr, "//", 2) == 0) || (*ptr == '\n'))
                    if ( (*ptr) == '\0' || (*ptr) == '#' || (*ptr) == '\n' || ((*ptr)=='/' && *(ptr+1)=='/'))
                    {
                        continue;
                    }

                    if (*ptr == '[')
                    {
                        break;
                    }
                    //key = "value contains space" #注释 || key = value //注释
                    //memset(sBuf, 0, sizeof(sBuf));
                    i = 0;
                    while ( (*ptr != '\n') && (*ptr != '\0') && (*ptr != '=') )
                    {
                        while(isspace(*ptr)) { ptr++; continue; }
                        if (*ptr == '\0' || *ptr == '=') break;
                        //取得配置名称
                        sBuf[i] = *ptr;
                        ptr++;
                        i++;
                    }
                    sBuf[i]='\0';
                    //找到指定的KEY
                    if (strcmp(sBuf, psItemName) == 0)
                    {
                        ptr++;
                        iItemFoundFlg = 1;
                        //走过= 后面的空格
                        while(isspace(*ptr)) { ptr++ ; }

                        int j = 0; psItemVal[0]='\0';
                        while (j < valLen-1 && (*ptr != '\0') && (*ptr != '\n') && !isspace(*ptr))
                        {
                            //防止取到域的注释内容
                            if ((*ptr) == '#' || ((*ptr)=='/' && *(ptr+1)=='/'))
                            {
                                break;
                            }

                            if (*ptr == '"' || *ptr == '\'') {
                                ptr++;
                                while (j < valLen-1 && (*ptr != '\0') && (*ptr != '\n') && (*ptr != '"')
                                    && (*ptr != '\'') && (*ptr) != '#') {
                                    if ((*ptr)=='/' && *(ptr+1)=='/') break;
                                    psItemVal[j++] = *ptr++;
                                }
                                str_rtrim(psItemVal);
                                break;
                            }
                            psItemVal[j] = *ptr;

                            ptr++;
                            j++;
                        }
                        psItemVal[j] = '\0';
                        break;
                    }

                    //memset(sLine, 0, sizeof(sLine));
                }

                if (iItemFoundFlg != 1)
                {
                    snprintf(psErrMsg, iErrLen, "item not found, section[%s], item[%s]", psSectionName, psItemName);
                    fclose(fp);
                    return -1;
                }
                break;
            }
        }
        //memset(sLine, 0U, sizeof(sLine));
    }

    if (iSecFoundFlg != 1)
    {
        snprintf(psErrMsg, iErrLen, "section not found, section[%s]", psSectionName);
        fclose(fp);
        return -1;
    }

    fclose(fp);

	// add by s.z.c 2006/05/29
	while( --valLen >= 0 ) {
		if( psItemVal[valLen] == '\r' ) {
			psItemVal[valLen] = '\0';
		}
	}

    return 0;
}

#ifdef  __cplusplus
}
#endif

