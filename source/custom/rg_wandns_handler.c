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

static oid saRgIpMgmtWanMode_lastOid = 1;
static oid saRgIpMgmtWanMtu_lastOid = 2;
static oid saRgIpMgmtWanTtl_lastOid = 3;

static int getRgIpMgmtWanDns(int *value, oid lastOid)
{
    char dmStr[256];
    char retStrVal[256];
    int status;

    if (value == NULL)
        return -1;
    
    memset(dmStr, 0, sizeof(dmStr));
    memset(retStrVal,0, sizeof(retStrVal));

    sprintf(dmStr, "com.cisco.spvtg.ccsp.pam.Helper.FirstUpstreamIpInterface");

    if (get_dm_value(dmStr, retStrVal, sizeof(retStrVal))){
        return -1;
    }

    memset(dmStr, 0, sizeof(dmStr));

    if (lastOid == saRgIpMgmtWanMtu_lastOid){
        sprintf(dmStr, "%s" "MaxMTUSize", retStrVal);
    }else if(lastOid == saRgIpMgmtWanTtl_lastOid){
        sprintf(dmStr, "%s" "X_CISCO_COM_WanTTL", retStrVal);
    }else
        return -1;

    memset(retStrVal, 0, sizeof(retStrVal));
    if (get_dm_value(dmStr, retStrVal, sizeof(retStrVal)))
        return -1;
    
    *value = atoi(retStrVal);
    
    return 0;
}

static int setRgIpMgmtWanDns(int value, oid lastOid)
{
    char dmStr[256];
    char strVal[256];
    int status;
    
    memset(dmStr, 0, sizeof(dmStr));
    memset(strVal,0, sizeof(strVal));

    sprintf(dmStr, "com.cisco.spvtg.ccsp.pam.Helper.FirstUpstreamIpInterface");

    if (get_dm_value(dmStr, strVal, sizeof(strVal))){
        return -1;
    }

    memset(dmStr, 0, sizeof(dmStr));

    if (lastOid == saRgIpMgmtWanMode_lastOid){
        sprintf(dmStr, "Device.X_CISCO_COM_DeviceControl.WanAddressMode");
    }
    else if (lastOid == saRgIpMgmtWanMtu_lastOid){
        sprintf(dmStr, "%s" "MaxMTUSize", strVal);
    }else if(lastOid == saRgIpMgmtWanTtl_lastOid){
        sprintf(dmStr, "%s" "X_CISCO_COM_WanTTL", strVal);
    }else
        return -1;

    memset(strVal, 0, sizeof(strVal));

    if (lastOid == saRgIpMgmtWanMode_lastOid){
        switch (value) {
            case 1:
                sprintf(strVal, "DHCP");
                break;
            case 2:
                sprintf(strVal, "Static");
                break;
        }
    }
    else
        sprintf(strVal, "%d", value);

    if (set_dm_value(dmStr, strVal, sizeof(strVal))){
        return -1;
    }

    char rebootStr[] = "Device delay";
    char rebootObj[] = "Device.X_CISCO_COM_DeviceControl.RebootDevice";
    if (lastOid == saRgIpMgmtWanMode_lastOid){
        /* CID: 67915 Unchecked return value*/
        if(set_dm_value(rebootObj, rebootStr, sizeof(rebootStr))) {
           return -1;
        }
    }

    return 0;
}

int
handleWanDnsRequest(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
)
{
    netsnmp_request_info   *request     = NULL;
    netsnmp_variable_list  *requestvb   = NULL;
    oid                     subid       = 0;
    int                     value       = 0;
    int                     ret;
    char *pDestComponentName = NULL;
    char *pDestPath = NULL;
    
    for (request = requests; request != NULL; request = request->next) {

        requestvb = request->requestvb;
        subid = requestvb->name[requestvb->name_length - 2]; /* For scalar the last oid should be "0" */

        switch (reqinfo->mode){
            case MODE_GET:
                if( subid  == saRgIpMgmtWanMtu_lastOid){
                    if (!getRgIpMgmtWanDns(&value, subid)){
                        snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&value, sizeof(value));
                        request->processed = 1;
                    }
                }
                else if (subid == saRgIpMgmtWanTtl_lastOid){
                    if (!getRgIpMgmtWanDns(&value, subid)){
                        snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&value, sizeof(value));
                        request->processed = 1;
                    }
                }
                break;
                
            case MODE_SET_RESERVE1:
                ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
                if (ret != SNMP_ERR_NOERROR)
                    netsnmp_set_request_error(reqinfo, requests, ret);
                request->processed = 1;     /* request->processed will be reset in every step by netsnmp_call_handlers */
                break;

            case MODE_SET_RESERVE2:
                if (subid == saRgIpMgmtWanMode_lastOid){
                    if (!setRgIpMgmtWanDns(*requestvb->val.integer, subid))
                        request->processed = 1;
                }
                else if( subid  == saRgIpMgmtWanMtu_lastOid){
                    if (!setRgIpMgmtWanDns(*requestvb->val.integer, subid))
                        request->processed = 1;
                }
                else if (subid == saRgIpMgmtWanTtl_lastOid){
                    if (!setRgIpMgmtWanDns(*requestvb->val.integer, subid))
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

#define DNSSERVER_DM "Device.DNS.Client.Server.%d.DNSServer"
#define DnsServerIpv4_lastoid 3
#define DnsServerIpv6_lastoid 4

static int verifyDNSServerType(PCCSP_TABLE_ENTRY pEntry, oid lastOid)
{
    char dmStr[128] = {'\0'};
    char value[64]={'\0'};

    snprintf(dmStr, sizeof(dmStr), DNSSERVER_DM, pEntry->IndexValue[0].Value.uValue);

    get_dm_value(dmStr, value, 32);

    if (strstr(value,":")) {

        return ( DnsServerIpv6_lastoid == lastOid );
    }
    else {

        return ( DnsServerIpv4_lastoid == lastOid );
   }

}

int
handleDnsServer(
    netsnmp_mib_handler			*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		*requests
)
{
    netsnmp_request_info   *request     = NULL;
    netsnmp_variable_list  *requestvb   = NULL;
    oid                     subid       = 0;
    PCCSP_TABLE_ENTRY entry 		= NULL;


    for (request = requests; request != NULL; request = request->next) {

        requestvb = request->requestvb;

        subid = requestvb->name[requestvb->name_length - 2];

        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
        if (entry == NULL) {
	    netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
	    CcspTraceError(("No entry found for DNS Servers!\n"));
	    continue;
        }

        switch (reqinfo->mode){

            case MODE_GET:
		if ((subid == DnsServerIpv4_lastoid) ||
		     (subid == DnsServerIpv6_lastoid)) {

		     if (!verifyDNSServerType(entry,subid)) {

		         netsnmp_tdata_row* row = netsnmp_tdata_extract_row(request);
			 netsnmp_remove_tdata_row(request,row);
		     }
		}
		break;
	    default:
		break;
	}

    }

    return SNMP_ERR_NOERROR;

}
