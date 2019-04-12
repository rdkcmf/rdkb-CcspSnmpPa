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
#include "ccsp_snmp_common.h"
#include "ccsp_mib_definitions.h"
#include "cosa_api.h"

static oid saRgIpMgmtApplySettings_lastOid = 1001;
static oid saRgIpMgmtLanAddrInterface_oid = 9; 

static char *dhcpdstComp = NULL, *dhcpdstPath = NULL; /* cache */

#define IPMGNT_DM_OBJ "Device.DHCPv4."
#define IPMGMTLANADDRINTERFACE_DM_PAT "Device.DHCPv4.Server.Pool.%d.Client.%d.X_CISCO_COM_Interface"

static BOOL FindIpMgntDestComp(void)
{
    if (dhcpdstComp && dhcpdstPath)
        return TRUE;

    if (dhcpdstComp)
        AnscFreeMemory(dhcpdstComp);
    if (dhcpdstPath)
        AnscFreeMemory(dhcpdstPath);
    dhcpdstComp = dhcpdstPath = NULL;

    if (!Cosa_FindDestComp(IPMGNT_DM_OBJ, &dhcpdstComp, &dhcpdstPath)
            || !dhcpdstComp || !dhcpdstPath)
    {
        CcspTraceError(("%s: fail to find dest comp\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

int handleIpMgmtRequests(
    netsnmp_mib_handler           *handler,
    netsnmp_handler_registration  *reginfo,
    netsnmp_agent_request_info    *reqinfo,
    netsnmp_request_info          *requests)
{
    netsnmp_request_info     *request      = NULL;
    netsnmp_variable_list    *requestvb    = NULL;
    int                      ret;
    oid                      subid         = 0;
    int                      value         = 2; /* TruthValue: true(1), false(2) */

    for (request = requests; request != NULL; request = request->next){
        requestvb = request->requestvb;
        subid = requestvb->name[requestvb->name_length - 2];

        switch(reqinfo->mode){
            case MODE_GET:
                if (subid == saRgIpMgmtApplySettings_lastOid){
                    /* always return false when get */
                    value = 2;
                    snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&value, sizeof(value));
                    request->processed = 1;
                }
                
                break;

            case MODE_SET_RESERVE1:
                ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
                if (ret != SNMP_ERR_NOERROR)
                    netsnmp_set_request_error(reqinfo, requests, ret);
                request->processed = 1;     /* request->processed will be reset in every step by netsnmp_call_handlers */
                break;

            case MODE_SET_RESERVE2:
                if( subid  == saRgIpMgmtApplySettings_lastOid){
                    /* do nothing */
                    request->processed = 1;
                }
                break;
                
            case MODE_SET_ACTION:
                break;
                
            case MODE_SET_FREE:
            case MODE_SET_COMMIT:
            case MODE_SET_UNDO:
                break;
            
            default:
                return SNMP_ERR_GENERR;
        }
    }
    
    return SNMP_ERR_NOERROR;
}


static void getInterface(PCCSP_TABLE_ENTRY entry, char* interface ){
    parameterValStruct_t **valStr;
    int nval = -1;
    char str[80];
    char * name = (char*) str;
    
    if(FALSE == FindIpMgntDestComp())
    {
        goto ERR; 
    } 
    
    snprintf(name, sizeof(str),IPMGMTLANADDRINTERFACE_DM_PAT,entry->IndexValue[0].Value.uValue, entry->IndexValue[1].Value.uValue);

    if (!Cosa_GetParamValues(dhcpdstComp, dhcpdstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s \n", __FUNCTION__, name[0]));
        goto ERR;
    }
    if(nval < 1){
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        goto ERR;
    }

    if(strstr(valStr[0]->parameterValue, "Ethernet")){
        strcpy(interface, "LAN"); 
    }else if(strstr(valStr[0]->parameterValue, "SSID.1")){
        strcpy(interface, "WiFi-2.4");
    }else if(strstr(valStr[0]->parameterValue, "SSID.2")){
        strcpy(interface, "WiFi-5");
    }else if(strstr(valStr[0]->parameterValue, "MoCA")){
        strcpy(interface, "MoCA");
    }else
        strcpy(interface, "Unknow");

    if (nval > 0)
    {
        Cosa_FreeParamValues(nval, valStr);
    }
    return;

ERR:
    strcpy(interface, "Unknow");
    return;
}

int
handlerIpMgntLanAddrTable(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
)
{
    netsnmp_request_info* req;
    int subid;
    char strval[10];
    int retval=SNMP_ERR_NOERROR;
    PCCSP_TABLE_ENTRY entry = NULL;
    netsnmp_variable_list *vb = NULL;
    for (req = requests; req != NULL; req = req->next)
    {
        vb = req->requestvb;
        subid = vb->name[vb->name_length -3];
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            continue;
        }
        switch (reqinfo->mode) {
            case MODE_GET:
                if (subid == saRgIpMgmtLanAddrInterface_oid ) {
                    getInterface(entry, strval);
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&strval, strlen(strval));
                    req->processed = 1;
                }
                break;

            case MODE_SET_RESERVE1:
                break;

            case MODE_SET_RESERVE2:
                break;

            case MODE_SET_ACTION:
                /* commit */

                break;

            case MODE_SET_FREE:
                
                break;

            case MODE_SET_COMMIT:
            case MODE_SET_UNDO:
                /* nothing */
                break;

            default:
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
                return SNMP_ERR_GENERR;
        }
    }

    return SNMP_ERR_NOERROR;
}

