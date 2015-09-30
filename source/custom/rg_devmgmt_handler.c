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

#define TRUE 1
#define FALSE 0

#define IANA_ORIGIN_DM "Device.IP.Interface.1.IPv6Address.%d.Origin"
#define IANA_ORIGIN_DHCPv6 "DHCPv6"

#define IAPD_PREFIXLENGTH_SUBID 4
#define IAPD_PREFIXVALUE_SUBID 5
#define IAPD_PREFIX_DM "Device.IP.Interface.1.IPv6Prefix.%d.Prefix"

typedef union iapd_s {
    char prefix_value[40];
    int  prefix_length;
}iapd_t;


static int is_iana_addr(int index)
{
    char dm_str[64] = {'\0'};
    char iana_origin[32] = {'\0'};

    snprintf(dm_str, sizeof(dm_str), IANA_ORIGIN_DM, index);

    if(get_dm_value(dm_str, iana_origin, sizeof(iana_origin))) {
        AnscTraceError(("%s failed to get %s.\n", __func__, dm_str));
        return FALSE;
    }

    if (strncmp(IANA_ORIGIN_DHCPv6, iana_origin, strlen(IANA_ORIGIN_DHCPv6))) {
        AnscTraceError(("IANA ORIGIN \"%s\".\n", iana_origin));
        return FALSE;
    }

    return TRUE;
}

static int iapd_handler(int lastOid, int insNum, iapd_t *pIapd)
{
    char dm_str[64] = {'\0'}, prefix[64] = {'\0'};
    char *pLen, *saveptr, *pVal;
    int i=0;

    if (pIapd == NULL) {
        AnscTraceError(("%s invalid parameter.\n", __func__));
        return FALSE;
    }

    snprintf(dm_str, sizeof(dm_str), IAPD_PREFIX_DM, insNum);

    if(get_dm_value(dm_str, prefix, sizeof(prefix))) {
        AnscTraceError(("%s failed to get %s.\n", __func__, dm_str));
        return FALSE;
    }

    if (lastOid == IAPD_PREFIXLENGTH_SUBID) {
        pLen = strrchr(prefix, '/');
        if (!pLen) {
            AnscTraceError(("%s wrong backend value %s.\n", __func__, prefix));
            return FALSE;
        }else{
            pLen++; // skip '/'
            pIapd->prefix_length = atoi(pLen);
        }
    }else if (lastOid == IAPD_PREFIXVALUE_SUBID) { 
        pVal = strtok(prefix, "/");
        if(!pVal) {
            AnscTraceError(("%s wrong backend value %s.\n", __func__, prefix));
            return FALSE;
        }else 
            strncpy(pIapd->prefix_value, pVal, sizeof(pIapd->prefix_value));
    }else{
        AnscTraceError(("%s unexpected lastOid %d.\n", __func__, lastOid));
        return FALSE;
    }
   
    return TRUE;
}

int
handleIanaTable(
    netsnmp_mib_handler             *handler,
    netsnmp_handler_registration    *reginfo,
    netsnmp_agent_request_info      *reqinfo,
    netsnmp_request_info            *requests
)
{
    netsnmp_request_info* req;
    int subid;
    int intval, status;
    int retval=SNMP_ERR_NOERROR;
    PCCSP_TABLE_ENTRY entry = NULL; 
    netsnmp_variable_list *vb = NULL;
    int index;

    for (req = requests; req != NULL; req = req->next) {
        vb = req->requestvb;
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceError(("No entry found for IA_NA table.\n"));
            continue;
        }

        index = entry->IndexValue[0].Value.iValue;
        if (is_iana_addr(index) != TRUE) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceError(("Instance number %d are not IA_NA address entry.\n", index));
            continue;
        }
        
        switch (reqinfo->mode) {
            case MODE_GET:
        
                break;

            default:
                netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                return SNMP_ERR_GENERR;
        }
    }
    return SNMP_ERR_NOERROR;
}

int
handleIapdTable(
    netsnmp_mib_handler             *handler,
    netsnmp_handler_registration    *reginfo,
    netsnmp_agent_request_info      *reqinfo,
    netsnmp_request_info            *requests
)
{
    netsnmp_request_info* req;
    int subid, intval, status;
    int retval=SNMP_ERR_NOERROR;
    PCCSP_TABLE_ENTRY entry = NULL; 
    netsnmp_variable_list *vb = NULL;
    int index;
    iapd_t iapd;

    memset(&iapd, 0, sizeof(iapd));

    for (req = requests; req != NULL; req = req->next) {
        vb = req->requestvb;
        subid = vb->name[vb->name_length -2];
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceError(("No entry found for IA_PD table.\n"));
            continue;
        }

        index = entry->IndexValue[0].Value.iValue;
        
        switch (reqinfo->mode) {
        case MODE_GET:

            if ((subid == IAPD_PREFIXLENGTH_SUBID) || 
                (subid == IAPD_PREFIXVALUE_SUBID)) {
                if(iapd_handler(subid, index, &iapd) != TRUE) {
                    AnscTraceError(("%s iapd_handler failed.\n"));
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                    break;
                }
            }

            if (subid == IAPD_PREFIXLENGTH_SUBID){              
                AnscTraceWarning(("prefix length %d.\n", iapd.prefix_length));
                snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&iapd.prefix_length, sizeof(iapd.prefix_length));             
                req->processed = 1;

            } else if (subid == IAPD_PREFIXVALUE_SUBID){
                AnscTraceWarning(("prefix value %s.\n", iapd.prefix_value));
                snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)iapd.prefix_value, strlen(iapd.prefix_value));
                req->processed = 1;
            }

            break;

        default:
            netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
            return SNMP_ERR_GENERR;
        }
    }
    return SNMP_ERR_NOERROR;
}

/* saRgDeviceConfigSnmpEnable */
struct snmpenable_info_s {
    const char *str;
    int bitmap;
};

#define BIT(x) (1 << (x))
#define SnmpEnable_lastoid 4
#define SNMPENABLE_DM "Device.X_CISCO_COM_DeviceControl.SNMPEnable"

enum SnmpEnable_e {
    RG_WAN = 0,
    RG_DUALIP,
    RG_LAN,
    SNMPENABLE_MAX
};

static const struct 
snmpenable_info_s gSnmpEnableInfo[] = {
    [RG_WAN] = {
        .str = "rgWan",
        .bitmap = BIT(7)
    },
    [RG_DUALIP] = {
        .str = "rgDualIp",
        .bitmap = BIT(6),
    },
    [RG_LAN] = {
        .str = "rgLanIp",
        .bitmap = BIT(5)
    },
};

static int get_snmp_enable(unsigned char *octet)
{
    char strVal[64] = {'\0'};
    char *ptr, *substr, *saveptr;
    int i;

    if(octet == NULL) 
        return FALSE;

    if(get_dm_value(SNMPENABLE_DM, strVal, sizeof(strVal))) 
        return FALSE;

    for(ptr=strVal; ;ptr=NULL) {
        substr = strtok_r(ptr, ",", &saveptr);
        if(substr == NULL) 
            break;

        for(i=0; i<SNMPENABLE_MAX; i++) {
            if(strcasecmp(substr, gSnmpEnableInfo[i].str) == 0) {
                *octet |= gSnmpEnableInfo[i].bitmap;
                break;
            }
        }
    }

    return TRUE;
}

static int set_snmp_enable(const char *octet)
{
    int bits, i, j = 0;
    char strval[64] = {'\0'};

    sprintf(strval, "%x", octet[0]);    /* one octet */
    bits = strtoul(strval, NULL, 16);

    bzero(strval, sizeof(strval));

    for(i=0; i<SNMPENABLE_MAX; i++) {
        if(bits & gSnmpEnableInfo[i].bitmap) {
            if(j==0) 
                _ansc_strcpy(strval, gSnmpEnableInfo[i].str);
            else{
                _ansc_strcat(strval, ",");
                _ansc_strcat(strval, gSnmpEnableInfo[i].str);
            }
            j++;
        }
    }

    if(set_dm_value(SNMPENABLE_DM, strval, strlen(strval))) 
        return FALSE;

    return TRUE;
}

int
handleDeviceConfig(
    netsnmp_mib_handler             *handler,
    netsnmp_handler_registration    *reginfo,
    netsnmp_agent_request_info      *reqinfo,
    netsnmp_request_info            *requests
)
{
    netsnmp_request_info* request;
    netsnmp_variable_list *requestvb    = NULL;
    int subid, ret;
    int retval=SNMP_ERR_NOERROR;
    netsnmp_variable_list *vb = NULL;
    unsigned char octet = 0;
    
    for (request = requests; request != NULL; request = request->next) {
        requestvb = request->requestvb;
        subid = requestvb->name[requestvb->name_length - 2];

        switch(reqinfo->mode){
        case MODE_GET:
            if(subid == SnmpEnable_lastoid) {
                if(get_snmp_enable(&octet) == TRUE) 
                    snmp_set_var_typed_value(requestvb, (u_char)ASN_OCTET_STR, (u_char *)&octet, sizeof(octet));
                else
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);

                request->processed = 1;
            }
            break;

        case MODE_SET_RESERVE1:
            if(subid == SnmpEnable_lastoid) {
                ret = netsnmp_check_vb_type(requestvb, ASN_OCTET_STR);
                if (ret != SNMP_ERR_NOERROR)
                    netsnmp_set_request_error(reqinfo, requests, ret);
                if(requestvb->val_len != 1) /* one octet */
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGVALUE);
                request->processed = 1;     /* request->processed will be reset in every step by netsnmp_call_handlers */
            }
            break;

        case MODE_SET_RESERVE2:
            if(subid == SnmpEnable_lastoid) {
                if(set_snmp_enable(requestvb->val.string) != TRUE) {
                    AnscTraceError(("%s set failed.\n", SNMPENABLE_DM));
                    netsnmp_request_set_error(request, SNMP_ERR_GENERR);
                }
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
} /* saRgDeviceConfigSnmpEnable end */
