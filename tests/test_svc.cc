#include <cassert>
#include <cstdio>
#include <cstring>
#include "../include/nescasvc.h"

int main(void)
{
	int ml=0;
	/* id -> name */
	assert(strcmp(ncs_svc_name(0),"http")==0);   /* S_HTTP */
	assert(strcmp(ncs_svc_name(1),"ftp")==0);    /* S_FTP  */
	assert(strcmp(ncs_svc_name(2),"rtsp")==0);   /* S_RTSP */
	assert(strcmp(ncs_svc_name(8),"hikvision")==0); /* S_HIK long name */
	assert(strcmp(ncs_svc_name(99),"???")==0);

	/* prefix -> id (+ matched length) */
	assert(ncs_svc_id_prefix("http80",&ml)==0 && ml==4);
	assert(ncs_svc_id_prefix("rtsp554",&ml)==2 && ml==4);
	assert(ncs_svc_id_prefix("ssh22",&ml)==3 && ml==3);
	assert(ncs_svc_id_prefix("smtp25",&ml)==7 && ml==4); /* not confused with ssh */
	assert(ncs_svc_id_prefix("hik8000",&ml)==8 && ml==3);
	assert(ncs_svc_id_prefix("webform8080",&ml)==6 && ml==7); /* longest wins over wf */
	assert(ncs_svc_id_prefix("nope",&ml)==-1 && ml==0);

	/* default ports */
	assert(ncs_svc_defport(1)==21);
	assert(ncs_svc_defport(2)==554);
	printf("test_svc: all passed\n");
	return 0;
}
