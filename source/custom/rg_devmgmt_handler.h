/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#ifndef __RG_DEVMGMT_HANDLER_H__
#define __RG_DEVMGMT_HANDLER_H__

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#define MAX_PARAM_NAME_LENGTH       256

typedef struct _oidMap
{
    char    oid[MAX_PARAM_NAME_LENGTH];
    char    paramName[MAX_PARAM_NAME_LENGTH];
    u_char  type;
} oidMap_t;

int
getOid
    (
        netsnmp_request_info    *request,
        char                    *retOidBuf,
        size_t                  retBufSize
    );

int 
getParamNameFromMapTable
    (
        char*   oid, 
        char*   paramName,
        size_t  retBufSize
    );

u_char 
getParamTypeFromMapTable
    (
        char*       oid
    );

int doSnmpGet
    (
        netsnmp_request_info* request,
        netsnmp_agent_request_info* reqinfo
    );

int doSnmpTypeCheck
    (
        netsnmp_request_info* request,
        netsnmp_agent_request_info* reqinfo
    );

int doSnmpSet
    (
        netsnmp_request_info* request,
        netsnmp_agent_request_info* reqinfo
    );

#endif
