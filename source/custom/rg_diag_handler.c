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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "ansc_platform.h"
#include "cosa_api.h"
#include "ccsp_snmp_common.h"
#include "ccsp_mib_definitions.h"
#include <stdlib.h>



#define saRgSelfHealIpv4PingServerRowstatus_lastOid 3
#define saRgSelfHealIpv6PingServerRowstatus_lastOid 3


int handleipv4PingServerList(
    netsnmp_mib_handler           *handler,
    netsnmp_handler_registration  *reginfo,
    netsnmp_agent_request_info    *reqinfo,
    netsnmp_request_info          *requests)
{
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info     *request = NULL;
    netsnmp_variable_list    *vb = NULL;
    int                      rowstatus;
    oid                      subid = 0;
    PCCSP_TABLE_ENTRY        pEntry;
    
    printf(" ******** handleipv4PingServerList ************ \n");

    for (request = requests; request != NULL; request = request->next){
        vb = request->requestvb;
        subid = vb->name[vb->name_length - 2];
        
        printf(" **** handleipv4PingServerList subid is %lu ************ \n",subid);
        
        printf(" **** handleipv4PingServerList req is %ld ************ \n",*(vb->val.integer));

        if(subid == saRgSelfHealIpv4PingServerRowstatus_lastOid &&
           (*(vb->val.integer) == 4 || *(vb->val.integer) == 5)){
            // CreateAndWait or CreateAndGo let framework handle
        }else{
            pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
            if (pEntry == NULL) {
                netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
                CcspTraceWarning(("Entry not found for ipv4 server list\n"));
                continue;
            }
        }

        switch (reqinfo->mode) {
        case MODE_GET:
             if(subid == saRgSelfHealIpv4PingServerRowstatus_lastOid){
                rowstatus = 1; // RS_ACTIVE
                snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&rowstatus, sizeof(rowstatus));
                request->processed = 1;
            }
        break;

        case MODE_SET_RESERVE1:
            
            /* sanity check */
            break;

        case MODE_SET_RESERVE2:
            
            break;

        case MODE_SET_ACTION:
        /* commit */
        case MODE_SET_FREE:   
        case MODE_SET_COMMIT:
        case MODE_SET_UNDO:
        break;
        default:
            netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);
            return SNMP_ERR_GENERR;
        }
    }
    return SNMP_ERR_NOERROR;
}

int handleipv6PingServerList(
    netsnmp_mib_handler           *handler,
    netsnmp_handler_registration  *reginfo,
    netsnmp_agent_request_info    *reqinfo,
    netsnmp_request_info          *requests)
{
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info     *request = NULL;
    netsnmp_variable_list    *vb = NULL;
    int                      rowstatus;
    oid                      subid = 0;
    PCCSP_TABLE_ENTRY        pEntry;

    for (request = requests; request != NULL; request = request->next){
        vb = request->requestvb;
        subid = vb->name[vb->name_length - 2];

        if(subid == saRgSelfHealIpv6PingServerRowstatus_lastOid &&
           (*(vb->val.integer) == 4 || *(vb->val.integer) == 5)){
            // CreateAndWait or CreateAndGo let framework handle
        }else{
            pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
            if (pEntry == NULL) {
                netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
                CcspTraceWarning(("Entry not found for ipv6 server list\n"));
                continue;
            }
        }

        switch (reqinfo->mode) {
        case MODE_GET:
             if(subid == saRgSelfHealIpv6PingServerRowstatus_lastOid){
                rowstatus = 1; // RS_ACTIVE
                snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&rowstatus, sizeof(rowstatus));
                request->processed = 1;
            }
        break;

        case MODE_SET_RESERVE1:
            
            /* sanity check */
            break;

        case MODE_SET_RESERVE2:
            
            break;

        case MODE_SET_ACTION:
        /* commit */
        case MODE_SET_FREE:   
        case MODE_SET_COMMIT:
        case MODE_SET_UNDO:
        break;
        default:
            netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);
            return SNMP_ERR_GENERR;
        }
    }
    return SNMP_ERR_NOERROR;
}



