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

typedef struct fw_traffic_block_s fw_traffic_block_t;
struct fw_traffic_block_s {
    oid lastOid;
    const char *dmName;
    int maskValue;
};

struct block_day {
    int bitmap;
    const char *day;
};

#define saRgFwHttpBlock_lastOid   8
#define saRgFwP2PBlock_lastOid    9
#define saRgFwIdentBlock_lastOid  10
#define saRgFwIcmpBlock_lastOid   11
#define saRgFwMulticast_lastOid   12
#define saRgFwPortFilterBlockStarttime_lastOid 9
#define saRgFwPortFilterBlockEndtime_lastOid 10
#define saRgFwPortFilterBlockDays_lastOid 11
#define saRgFwPortFilterRowstatus_lastOid 2
#define saRgFwMacFilterBlockStarttime_lastOid 5
#define saRgFwMacFilterBlockEndtime_lastOid 6
#define saRgFwMacFilterBlockDays_lastOid 7
#define saRgFwMacFilterRowstatus_lastOid 2
#define saRgFwUrlFilterBlockStarttime_lastOid 6
#define saRgFwUrlFilterBlockEndtime_lastOid 7
#define saRgFwUrlFilterBlockDays_lastOid 8
#define saRgFwUrlFilterRowstatus_lastOid 2

#define FW_FACTORY_RESET_DM "Device.X_CISCO_COM_DeviceControl.FactoryReset"
#define FW_LEVEL_DM         "Device.X_CISCO_COM_Security.Firewall.FirewallLevel"
#define FW_HTTP_BLOCK_DM    "Device.X_CISCO_COM_Security.Firewall.FilterHTTP"
#define FW_P2P_BLOCK_DM     "Device.X_CISCO_COM_Security.Firewall.FilterP2P"
#define FW_ICMP_BLOCK_DM    "Device.X_CISCO_COM_Security.Firewall.FilterAnonymousInternetRequests"
#define FW_IDENT_BLOCK_DM   "Device.X_CISCO_COM_Security.Firewall.FilterIdent"
#define FW_MULTICAST_BLOCK_DM "Device.X_CISCO_COM_Security.Firewall.FilterMulticast"
#define PORT_FILTER_BLOCK_DAYS_DM "Device.X_Comcast_com_ParentalControl.ManagedServices.Service.%d.BlockDays"
#define MAC_FILTER_BLOCK_DAYS_DM "Device.X_Comcast_com_ParentalControl.ManagedDevices.Device.%d.BlockDays"
#define URL_FILTER_BLOCK_DAYS_DM "Device.X_Comcast_com_ParentalControl.ManagedSites.BlockedSite.%d.BlockDays"

#define COMCAST_FW_CUSTOM_LEVEL "Custom"

#define FW_BLOCK_IPSEC_MASK      (1 << 7)
#define FW_BLOCK_PPTP_MASK       (1 << 6)
#define FW_BLOCK_MULTICAST_MASK  (1 << 5)
#define FW_BLOCK_IDENT_MASK      (1 << 4)
#define FW_BLOCK_ICMP_MASK       (1 << 3)

#define FW_TRAFFIC_PASSTHRU_DEFAULT (FW_BLOCK_IPSEC_MASK     | \
                                     FW_BLOCK_PPTP_MASK      | \
                                     FW_BLOCK_MULTICAST_MASK | \
                                     FW_BLOCK_IDENT_MASK     | \
                                     FW_BLOCK_ICMP_MASK)

#define BITMAP_SUN   (1 << 7)
#define BITMAP_MON   (1 << 6)
#define BITMAP_TUE   (1 << 5)
#define BITMAP_WED   (1 << 4)
#define BITMAP_THU   (1 << 3)
#define BITMAP_FRI   (1 << 2)
#define BITMAP_SAT   (1 << 1)

#define ARRAY_SIZE(x) ((unsigned)(sizeof(x) / sizeof((x)[0])))

enum {
    SUN = 0,
    MON,
    TUE,
    WED,
    THU,
    FRI,
    SAT
};


static oid saRgFwTrafficPassthru_lastOid = 3;
static oid saRgFwWanBlockEnable_lastOid  = 4;
static oid saRgFwFactoryReset_lastOid = 1002;
static oid saRgFwApplySettings_lastOid = 1001;

static fw_traffic_block_t fwTrafficBlcok[] = {
    {saRgFwMulticast_lastOid, FW_MULTICAST_BLOCK_DM, FW_BLOCK_MULTICAST_MASK},
    {saRgFwIdentBlock_lastOid, FW_IDENT_BLOCK_DM,     FW_BLOCK_IDENT_MASK},
    {saRgFwIcmpBlock_lastOid, FW_ICMP_BLOCK_DM,      FW_BLOCK_ICMP_MASK},
    {saRgFwHttpBlock_lastOid, FW_HTTP_BLOCK_DM,      0},
    {saRgFwP2PBlock_lastOid, FW_P2P_BLOCK_DM,       0},
};

static struct block_day blockDays[] = {
    [SUN] = {
        .bitmap = BITMAP_SUN,
        .day    = "Sun"
    },
    [MON] = {
        .bitmap = BITMAP_MON,
        .day    = "Mon"
    },
    [TUE] = {
        .bitmap = BITMAP_TUE,
        .day    = "Tue"
    },
    [WED] = {
        .bitmap = BITMAP_WED,
        .day    = "Wed"
    },
    [THU] = {
        .bitmap = BITMAP_THU,
        .day    = "Thu"
    },
    [FRI] = {
        .bitmap = BITMAP_FRI,
        .day    = "Fri"
    },
    [SAT] = {
        .bitmap = BITMAP_SAT,
        .day    = "Sat"
    },
};

#ifdef CONFIG_CISCO_CCSP_PRODUCT_ARES

struct mac_filter_mode {
    const char *allowAll;
    const char *type;
};

#define MAC_FILTER_MODE_DM "Device.X_Comcast_com_ParentalControl.ManagedDevices.AllowAll"
#define MAC_FILTER_TYPE_DM "Device.X_Comcast_com_ParentalControl.ManagedDevices.Device.%d.Type"

#define macFilterMode_lastOid 5

enum {
    SNMP_BLOCK = 0,
    SNMP_PERMIT
};

static struct mac_filter_mode filterMode[] = {
    [SNMP_BLOCK] = {
        .allowAll = "true",
        .type     = "Block" 
    },
    [SNMP_PERMIT] = {
        .allowAll = "false",
        .type     = "Allow"
    },
};

static int mac_filter_get_mode(const char *dm, int *value)
{
    char strVal[64] = {'\0'};
    int i;

    if(dm == NULL || value == NULL) {
        AnscTraceWarning(("%s(%d) bad parameter.\n", __func__, __LINE__));
        return -1;
    }

    if(get_dm_value(dm, strVal, sizeof(strVal))) {
        AnscTraceWarning(("%s(%d) %s failed.\n", __func__, __LINE__, dm));
        return -1;
    }

    for(i=SNMP_BLOCK; i<=SNMP_PERMIT; i++) {
        if(strcmp(strVal, filterMode[i].allowAll) == 0) {
            *value = i;
            break;
        }
    }
    AnscTraceWarning(("%s(%d) value %d.\n", __func__, __LINE__, *value));

    return 0;
}

static int mac_filter_set_mode(const char *dm, int value)
{
    if(dm == NULL) 
        return -1;

    if(set_dm_value(dm, filterMode[value].allowAll, strlen(filterMode[value].allowAll))) {
        AnscTraceWarning(("%s(%d) %s set failed.\n", __func__, __LINE__, dm));
        return -1;
    }
    return 0;
}

#endif //endif CONFIG_CISCO_CCSP_PRODUCT_ARES

static int setFwFactoryReset(int value)
{
    if (value != 1){
        return -1; /* if not true, return inconsistent value */
    }

    if (set_dm_value(FW_FACTORY_RESET_DM, "Firewall", strlen("Firewall"))){
        return -1;
    }

    return 0;
}

static int isFwCustomLevel(void)
{
    char strVal[64] = {'\0'};

    if (get_dm_value(FW_LEVEL_DM, strVal, sizeof(strVal)))
        return 0;

    if (strcmp(strVal, COMCAST_FW_CUSTOM_LEVEL)){
        return 0;    /* If not at custom level, always return false */
    }

    return 1;
}

static int getFwCustomBlock(const oid lastOid, int *value)
{
    char strVal[64] = {'\0'};
    int i;

    if (NULL == value)
        return -1;

    if (!isFwCustomLevel()){
        *value = 2;
        return 0;
    }

    for (i = 0; i < ARRAY_SIZE(fwTrafficBlcok); i++) {
        if (lastOid == fwTrafficBlcok[i].lastOid)
            break;
    }

    /* not the OID we wanted */
    if (i >= ARRAY_SIZE(fwTrafficBlcok)) {
        return -1;
    }

    bzero(strVal, sizeof(strVal));
    if (get_dm_value(fwTrafficBlcok[i].dmName, strVal, sizeof(strVal)))
        return -1;
    if (!strcmp(strVal, "true"))
        *value = 1;
    else
        *value = 2;

    return 0;
}

static int setFwCustomBlock(const oid lastOid, int value)
{
    char strVal[64] = {'\0'};
    int i;
    
    if (value != 1 && value != 2)
        return -1;

    if (!isFwCustomLevel())
        return -1;

    for (i = 0; i < ARRAY_SIZE(fwTrafficBlcok); i++) {
        if (lastOid == fwTrafficBlcok[i].lastOid)
            break;
    }

    /* not the OID we wanted */
    if (i >= ARRAY_SIZE(fwTrafficBlcok)) {
        return -1;
    }

    bzero(strVal, sizeof(strVal));
    if (value == 1)
        strncpy(strVal, "true", sizeof(strVal));
    else 
        strncpy(strVal, "false", sizeof(strVal));

    if (set_dm_value(fwTrafficBlcok[i].dmName, strVal, strlen(strVal)))
        return -1;
    
    return 0;
}

int handleFwRequests(
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
                if (subid == saRgFwFactoryReset_lastOid){
                    /* always return false when get */
                    value = 2;
                    snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&value, sizeof(value));
                    request->processed = 1;
                }
                
                else if (subid == saRgFwApplySettings_lastOid){
                    /* always return false when get */
                    value = 2;
                    snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&value, sizeof(value));
                    request->processed = 1;
                }

                else if ((subid == saRgFwHttpBlock_lastOid) ||
                         (subid == saRgFwP2PBlock_lastOid)  ||
                         (subid == saRgFwIdentBlock_lastOid)||
                         (subid == saRgFwIcmpBlock_lastOid) ||
                         (subid == saRgFwMulticast_lastOid)){
                    if (!getFwCustomBlock(subid, &value)){
                        snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&value, sizeof(value));
                    }else{
                        netsnmp_set_request_error(reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
                    }
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
                if( subid  == saRgFwFactoryReset_lastOid){
                    if (setFwFactoryReset(*requestvb->val.integer)){
                        netsnmp_set_request_error(reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
                    }
                    request->processed = 1;
                }
                else if(subid == saRgFwApplySettings_lastOid){
                    /* do nothing */
                    request->processed = 1;
                }
                else if ((subid == saRgFwHttpBlock_lastOid) ||
                         (subid == saRgFwP2PBlock_lastOid)  ||
                         (subid == saRgFwIdentBlock_lastOid)||
                         (subid == saRgFwIcmpBlock_lastOid) ||
                         (subid == saRgFwMulticast_lastOid)){
                    if (setFwCustomBlock(subid, *requestvb->val.integer)){
                        netsnmp_set_request_error(reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
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
}

static int getFwTrafficBlock(unsigned char *value)
{
    int i;
    char strVal[64] = {'\0'};

    if (value == NULL)
        return -1;

    *value = FW_TRAFFIC_PASSTHRU_DEFAULT;

    if (!isFwCustomLevel()){
        return 0;
    }

    for (i = 0; i < 3; i++){    /* not include http & p2p */
        bzero(strVal, sizeof(strVal));
        get_dm_value(fwTrafficBlcok[i].dmName, strVal, sizeof(strVal));
        if (!strcmp(strVal, "false")){    /* not filter, then passthru */
            *value |= fwTrafficBlcok[i].maskValue;
        }else{
            *value &= ~fwTrafficBlcok[i].maskValue;
        }
    }
    return 0;
}

static int setFwTrafficBlock(unsigned char *strval)
{
    int i;
    unsigned int value = 0x0;

    if (strval == NULL)
        return -1;

    if (!isFwCustomLevel())   /* set firewall to custom level first */
        return -1;
    
    value = strtoul(strval, NULL, 16);

    for (i = 0; i < 3; i++){    /* not include http & p2p */
        if (value & fwTrafficBlcok[i].maskValue){    /* passthru */
            if (set_dm_value(fwTrafficBlcok[i].dmName, "false", strlen("false"))){
                return -1;
            }
        }else{  /* not passthru then block */
            if (set_dm_value(fwTrafficBlcok[i].dmName, "true", strlen("true"))){
                return -1;
            }
        }
    }
    
    return 0;
}

static int getFwWanBlock(unsigned char *value)
{
    int i;
    char strVal[64] = {'\0'};

    if (value == NULL)
        return -1;

    *value = 2;    /* default false */

    if (!isFwCustomLevel())
        return 0;

    for (i = 0; i < sizeof(fwTrafficBlcok)/sizeof(fwTrafficBlcok[0]); i++){
        bzero(strVal, sizeof(strVal));
        get_dm_value(fwTrafficBlcok[i].dmName, strVal, sizeof(strVal));
        if (!strcmp(strVal, "true")){    /* if filter, return true */
            *value = 1;
            break;
        }
    }
    return 0;
}


int handleFwBlockRequests(
    netsnmp_mib_handler           *handler,
    netsnmp_handler_registration  *reginfo,
    netsnmp_agent_request_info    *reqinfo,
    netsnmp_request_info          *requests)
{
    netsnmp_request_info     *request      = NULL;
    netsnmp_variable_list    *requestvb    = NULL;
    int                      ret;
    oid                      subid         = 0;
    unsigned char            value;
    unsigned char            strVal[64]    = {'\0'};

    for (request = requests; request != NULL; request = request->next){
        requestvb = request->requestvb;
        subid = requestvb->name[requestvb->name_length - 2];

        switch(reqinfo->mode){
            case MODE_GET:
                if (subid == saRgFwTrafficPassthru_lastOid){
                    if (!getFwTrafficBlock(&value)){
                        snmp_set_var_typed_value(request->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&value, sizeof(value));
                    }
                    request->processed = 1;
                }
                
                else if (subid == saRgFwWanBlockEnable_lastOid){
                    if (!getFwWanBlock(&value)){
                        snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&value, sizeof(value));
                    }
                    request->processed = 1;
                }

                break;

            case MODE_SET_RESERVE1:
                if (subid == saRgFwWanBlockEnable_lastOid){
                    ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
                }else if (subid == saRgFwTrafficPassthru_lastOid){
                    ret = netsnmp_check_vb_type(requests->requestvb, ASN_OCTET_STR);
                }else{
                    ret = SNMP_ERR_NOSUCHNAME;
                }

                if (ret != SNMP_ERR_NOERROR)
                    netsnmp_set_request_error(reqinfo, requests, ret);
                request->processed = 1;     /* request->processed will be reset in every step by netsnmp_call_handlers */
                break;

            case MODE_SET_RESERVE2:
                if (subid  == saRgFwTrafficPassthru_lastOid){
                    bzero(strVal, sizeof(strVal));
                    sprintf(strVal, "%x", requestvb->val.string[0]);  /* only 1 octet, OCTET->ASCII */
                    if (setFwTrafficBlock(strVal)){
                        netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_INCONSISTENTVALUE);
                    }
                    request->processed = 1;
                }
                else if(subid == saRgFwWanBlockEnable_lastOid){
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

static int validate_block_time(char *buf)
{
    int hour, minute;

    if (buf == NULL) 
        return -1;

    if (sscanf(buf, "%d:%d", &hour, &minute) != 2) 
        return -1;

    if(hour < 0 || hour > 24 || minute < 0 || minute > 60)
        return -1;
    
    return 0;
}

static int validate_block_days(const char *buf)
{
    char *substr=NULL, *str, *saveptr;
    char *save;
    int i, j, is_string_days = 0;
    int bitmap = 0, rc = 0;
    char strVal[64] = {'\0'};


    if(buf == NULL) 
        return -1;

    str = strdup(buf);
    save = str;

    for(j = 0; ; j++, str = NULL) {
        substr = strtok_r(str, ",", &saveptr);
        if(substr == NULL) 
            break;

        for (i=SUN; i<=SAT; i++) {
            if(strcasecmp(substr, blockDays[i].day) == 0) {
                is_string_days = 1;
                break;
            }
        }

        if (!is_string_days) {
            if(j != 0) {/* string: Mon, xxx */
                rc = -1;
                goto ret;
            }else {
                if(strlen(buf) != 1){ /* hex: 8080 -> only one octet */
                    rc = -1;
                    goto ret;
                } else 
                    break;
            }
        }
        is_string_days = 0;
    }

ret:
    if(save) 
        free(save);
    return rc;
}

static int get_block_days(const char *dmName, unsigned char *octet)
{
    char strVal[64] = {'\0'};
    char *ptr, *substr, *saveptr;
    int i;

    if(dmName == NULL || octet == NULL) 
        return -1;

    if(get_dm_value(dmName, strVal, sizeof(strVal))) 
        return -1;

    AnscTraceWarning(("%s(%d) strVal %s.\n", __func__, __LINE__, strVal));

    for(ptr=strVal; ; ptr=NULL) {
        substr = strtok_r(ptr, ",", &saveptr);
        if(substr == NULL) 
            break;
        AnscTraceWarning(("%s(%d) substr %s.\n", __func__, __LINE__, substr));

        for(i=SUN; i<=SAT; i++) {
            if(strcasecmp(substr, blockDays[i].day) == 0) {
                *octet |= blockDays[i].bitmap;
                break;
            }
        }
    }

    AnscTraceWarning(("%s(%d) octet 0x%x.\n", __func__, __LINE__, *octet));
    return 0;
}

static int set_block_days(const char *dmName, char *octetStr)
{
    char preStr[64] = {'\0'};
    int bitmap, i, j=0;

    if(dmName == NULL || octetStr == NULL) 
        return -1;

    sprintf(preStr, "%x", octetStr[0]);  // one octet str -> presentation
    bitmap = strtoul(preStr, NULL, 16);
    AnscTraceWarning(("%s(%d) bitmap 0x%x.\n", __func__, __LINE__, bitmap));

    bzero(preStr, sizeof(preStr));

    for(i=SUN; i<=SAT; i++) {
        if(bitmap & blockDays[i].bitmap) {
            if(j==0) 
                _ansc_strcpy(preStr, blockDays[i].day);
            else{
                _ansc_strcat(preStr, ",");
                _ansc_strcat(preStr, blockDays[i].day);
            }
            j++;
        }
    }

    AnscTraceWarning(("%s(%d) strVal %s.\n", __func__, __LINE__, preStr));
    if(set_dm_value(dmName, preStr, strlen(preStr)))
        return -1;
    return 0;
}

int handleFwPortFilter(
    netsnmp_mib_handler           *handler,
    netsnmp_handler_registration  *reginfo,
    netsnmp_agent_request_info    *reqinfo,
    netsnmp_request_info          *requests)
{
    netsnmp_request_info     *request = NULL;
    netsnmp_variable_list    *vb = NULL;
    int                      ins, rowstatus;
    oid                      subid = 0;
    PCCSP_TABLE_ENTRY        pEntry;
    char                     dmStr[128] = {'\0'};
    unsigned char            octet = 0;

    for (request = requests; request != NULL; request = request->next){
        vb = request->requestvb;
        subid = vb->name[vb->name_length - 2];

        if(subid == saRgFwPortFilterRowstatus_lastOid &&
           (*(vb->val.integer) == 4 || *(vb->val.integer) == 5)){
            // CreateAndWait or CreateAndGo let framework handle
        }else{
            pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
            if (pEntry == NULL) {
                netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
                AnscTraceWarning(("Entry not found for PortFilter\n"));
                continue;
            }
            ins = pEntry->IndexValue[0].Value.iValue;
        }

        switch (reqinfo->mode) {
        case MODE_GET:
            if(subid == saRgFwPortFilterBlockDays_lastOid) {

                snprintf(dmStr, sizeof(dmStr), PORT_FILTER_BLOCK_DAYS_DM, ins);
                AnscTraceWarning(("%s(%d) dmStr %s.\n", __func__, __LINE__, dmStr));

                if(get_block_days(dmStr, &octet) < 0) 
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);
                else 
                    snmp_set_var_typed_value(request->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&octet, sizeof(octet));

                request->processed = 1;
            }else if(subid == saRgFwPortFilterRowstatus_lastOid){
                rowstatus = 1; // RS_ACTIVE
                snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&rowstatus, sizeof(rowstatus));
                request->processed = 1;
            }
        break;

        case MODE_SET_RESERVE1:
            if (subid == saRgFwPortFilterBlockStarttime_lastOid ||
                subid == saRgFwPortFilterBlockEndtime_lastOid) {
                if(validate_block_time(vb->val.string) < 0) {
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGVALUE);

                    request->processed = 1;
                }
            }else if (subid == saRgFwPortFilterBlockDays_lastOid) {
                if(validate_block_days(vb->val.string) < 0){
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGVALUE);

                    request->processed = 1;
                }
            }
            /* sanity check */
            break;

        case MODE_SET_RESERVE2:
            if(subid == saRgFwPortFilterBlockDays_lastOid) {
                if(strlen(vb->val.string) == 1) { // hex format: one octet
                    snprintf(dmStr, sizeof(dmStr), PORT_FILTER_BLOCK_DAYS_DM, ins);
                    if(set_block_days(dmStr, vb->val.string) < 0) {
                        AnscTraceError(("%s set failed.\n", dmStr));
                        netsnmp_request_set_error(request, SNMP_ERR_GENERR);
                    }
                    request->processed = 1;
                }//else comma string use framework
            }
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

int handleFwMacFilter(
    netsnmp_mib_handler           *handler,
    netsnmp_handler_registration  *reginfo,
    netsnmp_agent_request_info    *reqinfo,
    netsnmp_request_info          *requests)
{
    netsnmp_request_info     *request = NULL;
    netsnmp_variable_list    *vb = NULL;
    int                      ins, rowstatus;
    oid                      subid = 0;
    PCCSP_TABLE_ENTRY        pEntry;
    char                     dmStr[128] = {'\0'};
    unsigned char            octet = 0;

    for (request = requests; request != NULL; request = request->next){
        vb = request->requestvb;
        subid = vb->name[vb->name_length - 2];

        if(subid == saRgFwMacFilterRowstatus_lastOid &&
           (*(vb->val.integer) == 4 || *(vb->val.integer) == 5)){
            // CreateAndWait or CreateAndGo let framework handle
        }else{
            pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
            if (pEntry == NULL) {
                netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
                AnscTraceWarning(("Entry not found for PortFilter\n"));
                continue;
            }
            ins = pEntry->IndexValue[0].Value.iValue;

#ifdef CONFIG_CISCO_CCSP_PRODUCT_ARES
            // comcast requirement: only show blocked or permitted devices
            {
                int snmpFilterMode=SNMP_BLOCK;
                char typeDm[128] = {'\0'}, typeVal[64] = {'\0'};

                if(reqinfo->mode == MODE_GET) {

                    if (mac_filter_get_mode(MAC_FILTER_MODE_DM, &snmpFilterMode) < 0){
                        netsnmp_request_set_error(request, SNMP_ERR_GENERR);
                        continue;
                    }
                    snprintf(typeDm, sizeof(typeDm), MAC_FILTER_TYPE_DM, ins);
                    if (get_dm_value(typeDm, typeVal, sizeof(typeVal))){
                        netsnmp_request_set_error(request, SNMP_ERR_GENERR);
                        continue;
                    }

                    if(strcmp(typeVal, filterMode[snmpFilterMode].type)) {
                        netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
                        AnscTraceWarning(("%s(%d) blockAll %d type %s.\n", __func__, __LINE__, snmpFilterMode, typeVal));
                        continue;
                    }
                }
            }
#endif // CONFIG_CISCO_CCSP_PRODUCT_ARES
        }

        switch (reqinfo->mode) {
        case MODE_GET:
            if(subid == saRgFwMacFilterBlockDays_lastOid) {

                snprintf(dmStr, sizeof(dmStr), MAC_FILTER_BLOCK_DAYS_DM, ins);
                AnscTraceWarning(("%s(%d) dmStr %s.\n", __func__, __LINE__, dmStr));

                if(get_block_days(dmStr, &octet) < 0) 
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);
                else 
                    snmp_set_var_typed_value(request->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&octet, sizeof(octet));

                request->processed = 1;
            }else if(subid == saRgFwMacFilterRowstatus_lastOid){
                rowstatus = 1; // RS_ACTIVE
                snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&rowstatus, sizeof(rowstatus));
                request->processed = 1;
            }
        break;

        case MODE_SET_RESERVE1:
            if (subid == saRgFwMacFilterBlockStarttime_lastOid ||
                subid == saRgFwMacFilterBlockEndtime_lastOid) {
                if(validate_block_time(vb->val.string) < 0) {
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGVALUE);

                    request->processed = 1;
                }
            }else if (subid == saRgFwMacFilterBlockDays_lastOid) {
                if(validate_block_days(vb->val.string) < 0){
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGVALUE);

                    request->processed = 1;
                }
            }
            /* sanity check */
            break;

        case MODE_SET_RESERVE2:
            if(subid == saRgFwMacFilterBlockDays_lastOid) {
                if(strlen(vb->val.string) == 1) { // hex format: one octet
                    snprintf(dmStr, sizeof(dmStr), MAC_FILTER_BLOCK_DAYS_DM, ins);
                    if(set_block_days(dmStr, vb->val.string) < 0) {
                        AnscTraceError(("%s set failed.\n", dmStr));
                        netsnmp_request_set_error(request, SNMP_ERR_GENERR);
                    }
                    request->processed = 1;
                }//else comma string use framework
            }else if(subid == saRgFwMacFilterRowstatus_lastOid){
                if(*(vb->val.integer) == 4) { // CreateAndGo
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
                    request->processed = 1;
                }
            }
            break;

        case MODE_SET_ACTION:

#ifdef CONFIG_CISCO_CCSP_PRODUCT_ARES
            {
                int snmpFilterMode;
                char typeDm[128] = {'\0'};
                PCCSP_TABLE_ENTRY pEntry;

                // set .Type when CreateAndWait
                if(subid == saRgFwMacFilterRowstatus_lastOid && *(vb->val.integer) == 5) {
                    pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
                    if(pEntry) {
                        ins = pEntry->IndexValue[0].Value.iValue;
                        AnscTraceWarning(("%s(%d) ins %d.\n", __func__, __LINE__, ins));

                        if(mac_filter_get_mode(MAC_FILTER_MODE_DM, &snmpFilterMode) < 0)
                            AnscTraceWarning(("%s(%d) %s failed.\n", __func__, __LINE__, MAC_FILTER_MODE_DM));
                        snprintf(typeDm, sizeof(typeDm), MAC_FILTER_TYPE_DM, ins);
                        if(set_dm_value(typeDm, filterMode[snmpFilterMode].type, strlen(filterMode[snmpFilterMode].type))) 
                            AnscTraceWarning(("%s(%d) %s set failed.\n", __func__, __LINE__, typeDm));
                    }
                }
            }

#endif // endif CONFIG_CISCO_CCSP_PRODUCT_ARES

        break;
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

int handleFwUrlKeywordFilter(
    netsnmp_mib_handler           *handler,
    netsnmp_handler_registration  *reginfo,
    netsnmp_agent_request_info    *reqinfo,
    netsnmp_request_info          *requests)
{
    netsnmp_request_info     *request = NULL;
    netsnmp_variable_list    *vb = NULL;
    int                      ins, rowstatus;
    oid                      subid = 0;
    PCCSP_TABLE_ENTRY        pEntry;
    char                     dmStr[128] = {'\0'};
    unsigned char            octet = 0;

    for (request = requests; request != NULL; request = request->next){
        vb = request->requestvb;
        subid = vb->name[vb->name_length - 2];

        if(subid == saRgFwUrlFilterRowstatus_lastOid &&
           (*(vb->val.integer) == 4 || *(vb->val.integer) == 5)){
            // CreateAndWait or CreateAndGo let framework handle
        }else{
            pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
            if (pEntry == NULL) {
                netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
                AnscTraceWarning(("Entry not found for PortFilter\n"));
                continue;
            }
            ins = pEntry->IndexValue[0].Value.iValue;
        }

        switch (reqinfo->mode) {
        case MODE_GET:
            if(subid == saRgFwUrlFilterBlockDays_lastOid) {

                snprintf(dmStr, sizeof(dmStr), URL_FILTER_BLOCK_DAYS_DM, ins);
                AnscTraceWarning(("%s(%d) dmStr %s.\n", __func__, __LINE__, dmStr));

                if(get_block_days(dmStr, &octet) < 0) 
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);
                else 
                    snmp_set_var_typed_value(request->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&octet, sizeof(octet));

                request->processed = 1;
            }else if(subid == saRgFwUrlFilterRowstatus_lastOid){
                rowstatus = 1; // RS_ACTIVE
                snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&rowstatus, sizeof(rowstatus));
                request->processed = 1;
            }
        break;

        case MODE_SET_RESERVE1:
            if (subid == saRgFwUrlFilterBlockStarttime_lastOid ||
                subid == saRgFwUrlFilterBlockEndtime_lastOid) {
                if(validate_block_time(vb->val.string) < 0) {
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGVALUE);

                    request->processed = 1;
                }
            }else if (subid == saRgFwUrlFilterBlockDays_lastOid) {
                if(validate_block_days(vb->val.string) < 0){
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGVALUE);

                    request->processed = 1;
                }
            }
            /* sanity check */
            break;

        case MODE_SET_RESERVE2:
            if(subid == saRgFwUrlFilterBlockDays_lastOid) {
                if(strlen(vb->val.string) == 1) { // hex format: one octet
                    snprintf(dmStr, sizeof(dmStr), URL_FILTER_BLOCK_DAYS_DM, ins);
                    if(set_block_days(dmStr, vb->val.string) < 0) {
                        AnscTraceError(("%s set failed.\n", dmStr));
                        netsnmp_request_set_error(request, SNMP_ERR_GENERR);
                    }
                    request->processed = 1;
                }//else comma string use framework
            }
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

// Comcast ARES specific handling
#ifdef CONFIG_CISCO_CCSP_PRODUCT_ARES

/*
 * Backend: .AllowAll -> boolean -> true/false 
 *          .Type     -> string  -> Allow/Block
 *  
 * Comcast GUI: 
 *          .AllowAll -> true --  .Type -> Block
 *              All Allowed  -> add blocked devices
 *          .AllowAll -> false -- .Type -> Allow
 *              All Blocked  -> add allowed devices
 * SNMP definition: 
 *          FilterMode -> block/permit
 *              block  ->  add block devices
 *              permit ->  add permit devices 
 * SNMP handling: 
 *          1. FilterMode -> block -> devices blocked
 *              .AllowAll -> true
 *              .Type     -> Block
 *          2. FilterMode -> permit -> devices allowed
 *              .AllowAll -> false
 *              .TYpe     -> Allow
 *          3. FilterMode switch from permit -> block
 *              Only show devices whose type are Block
 *          4. Vice versa
 */


int handleFirewallRules(
    netsnmp_mib_handler           *handler,
    netsnmp_handler_registration  *reginfo,
    netsnmp_agent_request_info    *reqinfo,
    netsnmp_request_info          *requests)
{
    netsnmp_request_info     *request = NULL;
    netsnmp_variable_list    *vb = NULL;
    int                      subid, mode=SNMP_BLOCK;


    for (request = requests; request != NULL; request = request->next){
        vb = request->requestvb;
        subid = vb->name[vb->name_length - 2];

        switch (reqinfo->mode) {
        case MODE_GET:
            if(subid == macFilterMode_lastOid) {
                if(mac_filter_get_mode(MAC_FILTER_MODE_DM, &mode) < 0)
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);
                else 
                    snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&mode, sizeof(mode));
                
                request->processed = 1;
            }
        break;

        case MODE_SET_RESERVE1:
            /* sanity check */
            break;

        case MODE_SET_RESERVE2:
            if(subid == macFilterMode_lastOid) {
                if(mac_filter_set_mode(MAC_FILTER_MODE_DM, *(vb->val.integer)) < 0)
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);

                request->processed = 1;
            }
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

/* Comcast specific handling of trusted computers for managed sites and managed services*/

#define IP_FILTER_MAX_ENTRIES 10

#define TRUSTED_USER_OBJ "Device.X_Comcast_com_ParentalControl.%s.TrustedUser."
#define TRUSTED_USER_IPADDR "Device.X_Comcast_com_ParentalControl.%s.TrustedUser.%d.IPAddress"
#define TRUSTED_USER_TRUST "Device.X_Comcast_com_ParentalControl.%s.TrustedUser.%d.Trusted"
#define HOSTS_HOST_IPADDR "Device.Hosts.Host.%d.IPAddress"

enum trusted_e {
    BLOCK = 1,
    PERMIT = 2
};

enum policy_e {
    URLKEYWORD = 1,
    PORT,
    NONE
};

enum ip_filter_lastoid_e {
    FILTER_ROWSTATUS = 2,
    ADDRESS_START_LASTOID,
    ADDRESS_END_LASTOID,
    FILTER_TRUSTED_LASTOID,
    FILTER_POLICY_LASTOID
};

struct trusted_user_entry {
    int ins[2];    // managed sites and services dm ins
    char start_ip[16];
    char end_ip[16];
    enum trusted_e trust;
    enum policy_e policy;
};

const static char* policy[] = {
    [URLKEYWORD] = "ManagedSites",
    [PORT]       = "ManagedServices"
};

const static char* trust[] = {
    [BLOCK] = "false",
    [PERMIT] = "true"
};

static struct trusted_user_entry ipFilter[IP_FILTER_MAX_ENTRIES];

static char *dstComp, *dstPath; /* cache */

static int find_ccsp_comp_path(void)
{
    if (dstComp && dstPath)
        return 0;

    if (dstComp)
        AnscFreeMemory(dstComp);
    if (dstPath)
        AnscFreeMemory(dstPath);
    dstComp = dstPath = NULL;

    if (!Cosa_FindDestComp("Device.Time.", &dstComp, &dstPath)
            || !dstComp || !dstPath)
    {
        AnscTraceError(("%s: fail to find dest comp\n", __FUNCTION__));
        return -1;
    }

    AnscTraceWarning(("dstComp %s, dstPath %s.\n", dstComp, dstPath));

    return 0;
}

/* 
 * Function: look up available entry 
 * Return: 
 *      avaiable match entry
 *      first unused entry and set default values
 *      NULL if exceed max number of entries
 */
static struct 
trusted_user_entry* lookup_trusted_user_entry(const char *ip)
{
    int i;

    for (i=0; i<IP_FILTER_MAX_ENTRIES; i++) {
        if(strcmp(ipFilter[i].start_ip, ip) == 0) 
            return &ipFilter[i];    // existing entry
    }

    for(i=0; i<IP_FILTER_MAX_ENTRIES; i++) {
        if(ipFilter[i].start_ip[0] == 0){
            // set default values
            strncpy(ipFilter[i].start_ip, ip, sizeof(ipFilter[i].start_ip));
            strncpy(ipFilter[i].end_ip, ip, sizeof(ipFilter[i].end_ip));
            ipFilter[i].trust = BLOCK;
            ipFilter[i].policy = NONE; 
            return &ipFilter[i];    // first unused entry
        }
    }

    // exceed max entries
    return NULL;
}


static void 
get_trusted_user_entry_values(const struct trusted_user_entry *pEntry, 
                              netsnmp_request_info *request)
{
    int subid;
    netsnmp_variable_list    *vb = NULL;
    int status; // RS_ACTIVE

    vb = request->requestvb;
    subid = vb->name[vb->name_length - 2];

    switch(subid) {
    case FILTER_ROWSTATUS:
        status = 1;
        snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&status, sizeof(status));
        request->processed = 1;
        break;
    case FILTER_TRUSTED_LASTOID:
        snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&pEntry->trust, sizeof(pEntry->trust));
        request->processed = 1;
        break;
    case FILTER_POLICY_LASTOID:
        if(pEntry->trust == PERMIT) 
            snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&pEntry->policy, sizeof(pEntry->policy));
        else{
            status = NONE;
            snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&status, sizeof(status));
        }
        request->processed = 1;
        break;
    default:
        break;
    }
}

static int 
commit_trusted_user_entry(struct trusted_user_entry *pUserEntry, const char *ip)
{
    int i;
    char dm[128] = {'\0'};
    parameterValStruct_t *pValueArray = NULL;

    AnscTraceWarning(("%s(%d): Entering...\n", __func__, __LINE__));

    // create the entry in ManagedSites table
    if(pUserEntry->ins[URLKEYWORD-1] == -1) {
        snprintf(dm, sizeof(dm), TRUSTED_USER_OBJ, policy[URLKEYWORD]);
        pUserEntry->ins[URLKEYWORD-1] = Cosa_AddEntry(dstComp, dstPath, dm);
        if(pUserEntry->ins[URLKEYWORD-1] == 0) {
            AnscTraceError(("%s(%d): failed to create entry %s.\n", __func__, __LINE__, dm));
            return SNMP_ERR_RESOURCEUNAVAILABLE;
        }
        AnscTraceWarning(("%s(%d): AddEntry %s %d.\n", __func__, __LINE__, dm, pUserEntry->ins[URLKEYWORD-1]));
    }

    // create the entry in ManagedServices table
    if(pUserEntry->ins[PORT-1] == -1) {
        snprintf(dm, sizeof(dm), TRUSTED_USER_OBJ, policy[PORT]);
        pUserEntry->ins[PORT-1] = Cosa_AddEntry(dstComp, dstPath, dm);
        if(pUserEntry->ins[PORT-1] == 0) {
            AnscTraceError(("%s(%d): failed to create entry %s.\n", __func__, __LINE__, dm));
            return SNMP_ERR_RESOURCEUNAVAILABLE;
        }
        AnscTraceWarning(("%s(%d): AddEntry %s %d.\n", __func__, __LINE__, dm, pUserEntry->ins[PORT-1]));
    }

    pValueArray = (parameterValStruct_t*)AnscAllocateMemory(sizeof(parameterValStruct_t)* 4);
    if(pValueArray == NULL) {
        AnscTraceError(("%s(%d): failed to create ccsp ValStruct.\n", __func__, __LINE__));
        return SNMP_ERR_RESOURCEUNAVAILABLE;
    }

    for(i=URLKEYWORD-1; i<PORT; i++) {
        snprintf(dm, sizeof(dm), TRUSTED_USER_IPADDR, policy[i+1], pUserEntry->ins[i]);
        pValueArray[i].parameterName = AnscCloneString(dm);
        pValueArray[i].type = ccsp_string;
        pValueArray[i].parameterValue = AnscCloneString(ip);
    }

    if(pUserEntry->trust == BLOCK) {
        for(i=PORT; i<4; i++) {
            snprintf(dm, sizeof(dm), TRUSTED_USER_TRUST, policy[i-PORT+1], pUserEntry->ins[i-PORT]);
            pValueArray[i].parameterName = AnscCloneString(dm);
            pValueArray[i].type = ccsp_boolean;
            pValueArray[i].parameterValue = trust[BLOCK];
        }
    }else{ // add trusted user
        if(pUserEntry->policy == PORT) {
            snprintf(dm, sizeof(dm), TRUSTED_USER_TRUST, policy[URLKEYWORD], pUserEntry->ins[URLKEYWORD-1]);
            pValueArray[2].parameterName = AnscCloneString(dm);
            pValueArray[2].type = ccsp_boolean;
            pValueArray[2].parameterValue = trust[BLOCK];

            snprintf(dm, sizeof(dm), TRUSTED_USER_TRUST, policy[PORT], pUserEntry->ins[PORT-1]);
            pValueArray[3].parameterName = AnscCloneString(dm);
            pValueArray[3].type = ccsp_boolean;
            pValueArray[3].parameterValue = trust[PERMIT];

        }else if(pUserEntry->policy == URLKEYWORD){
            snprintf(dm, sizeof(dm), TRUSTED_USER_TRUST, policy[URLKEYWORD], pUserEntry->ins[URLKEYWORD-1]);
            pValueArray[2].parameterName = AnscCloneString(dm);
            pValueArray[2].type = ccsp_boolean;
            pValueArray[2].parameterValue = trust[PERMIT];

            snprintf(dm, sizeof(dm), TRUSTED_USER_TRUST, policy[PORT], pUserEntry->ins[PORT-1]);
            pValueArray[3].parameterName = AnscCloneString(dm);
            pValueArray[3].type = ccsp_boolean;
            pValueArray[3].parameterValue = trust[BLOCK];
        }else {
            for(i=PORT; i<4; i++) {
                snprintf(dm, sizeof(dm), TRUSTED_USER_TRUST, policy[i-PORT+1], pUserEntry->ins[i-PORT]);
                pValueArray[i].parameterName = AnscCloneString(dm);
                pValueArray[i].type = ccsp_boolean;
                pValueArray[i].parameterValue = trust[PERMIT];
            }
        }
    }

    for(i=0; i<4; i++) 
        AnscTraceWarning(("param %d name %s value %s.\n", i, pValueArray[i].parameterName, pValueArray[i].parameterValue));

    Cosa_SetParamValuesNoCommit(dstComp,
                                dstPath,
                                pValueArray,
                                4);

    /* free the memory */
    if(pValueArray != NULL){
        for(i = 0; i < 4; i ++){
            if(pValueArray[i].parameterName != NULL)
                AnscFreeMemory(pValueArray[i].parameterName);

            if(pValueArray[i].parameterValue != NULL) 
                AnscFreeMemory(pValueArray[i].parameterValue);
        }
        AnscFreeMemory(pValueArray);
    }
    AnscTraceWarning(("%s(%d): Exiting...\n", __func__, __LINE__));

    return SNMP_ERR_NOERROR;

}

static int set_trusted_user_entry(netsnmp_request_info *requests)
{
    netsnmp_request_info *request = NULL;
    netsnmp_variable_list *vb = NULL;
    PCCSP_TABLE_ENTRY     pEntry = NULL;
    struct trusted_user_entry *pUserEntry = NULL;
    char dm[128] = {'\0'};
    char ip[64] = {'\0'};
    int subid, index, ins;
    int lastIndex = -1;

    AnscTraceWarning(("%s(%d): Entering...\n", __func__, __LINE__));

    for(request = requests; request != NULL; request = request->next) {
        vb = request->requestvb;
        subid = vb->name[vb->name_length - 2];
        index = vb->name[vb->name_length - 1];
        AnscTraceWarning(("%s(%d): subid %d index %d processed %d.\n", __func__, __LINE__, subid, index, request->processed));

        pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
        if (pEntry == NULL) {
            AnscTraceWarning(("No entry available for IpFilter\n"));
            netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
            continue;
        }
        ins = pEntry->IndexValue[0].Value.iValue;
        if(lastIndex != index) {
            snprintf(dm, sizeof(dm), HOSTS_HOST_IPADDR, ins);
            if(get_dm_value(dm, ip, sizeof(ip))) {
                AnscTraceError(("%s(%d) %s failed.\n", __func__, __LINE__, dm));
                netsnmp_request_set_error(request, SNMP_ERR_GENERR);
                continue;
            }
            pUserEntry = lookup_trusted_user_entry(ip);
            if(pUserEntry == NULL) {
                AnscTraceWarning(("No Entry available for IpFilter\n"));
                netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
                continue;
            }
            lastIndex = index;
        }
        AnscTraceWarning(("%s(%d): last time trust %d policy %d.\n", __func__, __LINE__, pUserEntry->trust, pUserEntry->policy));

        if(subid == FILTER_TRUSTED_LASTOID) {
            pUserEntry->trust = *(vb->val.integer);
            request->processed = 1;
        }else if(subid == FILTER_POLICY_LASTOID){
            pUserEntry->policy = *(vb->val.integer);
            request->processed = 1;
        }
    }

    return commit_trusted_user_entry(pUserEntry, ip);
}

static int load_trusted_user_entry(netsnmp_tdata *table)
{
    unsigned int *insArray = NULL;
    unsigned int insCount = 0;
    char pTemp[256] = {'\0'};
    char ip[64] = {'\0'}, trusted[64] = {'\0'};
    int i;  // policy loop
    int j;  // instance number array loop
    int k;  // trusted user entires loop
    struct trusted_user_entry *pEntry = NULL;

    AnscTraceWarning(("%s(%d): Entering...\n", __func__, __LINE__));

    for (k=0; k<IP_FILTER_MAX_ENTRIES; k++){
        memset(ipFilter[k].start_ip, 0, sizeof(ipFilter[k].start_ip));
        for(i=URLKEYWORD-1; i<PORT; i++)
            ipFilter[k].ins[i] = -1;
    }

    for(i=URLKEYWORD; i<=PORT; i++) {
        snprintf(pTemp, sizeof(pTemp), TRUSTED_USER_OBJ, policy[i]);

        if(Cosa_GetInstanceNums(dstComp, dstPath, pTemp, &insArray, &insCount)){
            AnscTraceWarning(("%s(%d): %s insCount %d.\n", __func__, __LINE__, pTemp, insCount));

            for(j=0; j<insCount; j++) {
                snprintf(pTemp, sizeof(pTemp), TRUSTED_USER_IPADDR, policy[i], insArray[j]);
                if(get_dm_value(pTemp, ip, sizeof(ip))) {
                    AnscTraceError(("%s(%d): %s failed.\n", __func__, __LINE__, pTemp));
                    continue;
                }

                snprintf(pTemp, sizeof(pTemp), TRUSTED_USER_TRUST, policy[i], insArray[j]);
                if(get_dm_value(pTemp, trusted, sizeof(trusted))) {
                    AnscTraceError(("%s(%d): %s failed.\n", __func__, __LINE__, pTemp));
                    continue;
                }

                AnscTraceWarning(("%s(%d): ip %s trusted %s.\n", __func__, __LINE__, ip, trusted));

                pEntry = lookup_trusted_user_entry(ip);
                if(pEntry) {
                    if(strcmp(trusted, "true") == 0){
                        pEntry->trust = PERMIT;
                        pEntry->policy |= i;
                    }else
                        pEntry->policy &= ~i;

                    if(pEntry->ins[i-1] == -1)
                        pEntry->ins[i-1] = insArray[j];

                    if(pEntry->start_ip[0] == 0) 
                        strncpy(pEntry->start_ip, ip, sizeof(pEntry->start_ip));
                }else{
                    AnscTraceError(("%s(%d): trusted user entry is full.\n", __func__, __LINE__));
                    return -1;
                }
            }
        }else{
            AnscTraceError(("%s(%d): No entries for %s.\n", __func__, __LINE__, pTemp));
            return -1;
        }
    }
    AnscTraceWarning(("%s(%d): Exiting...\n", __func__, __LINE__));

    return 0;
}

int handleFwIpFilterRefreshCache(netsnmp_tdata *table)
{
    if(find_ccsp_comp_path() < 0) 
        return -1;

    load_trusted_user_entry(table);
    return 0;
}

int handleFwIpFilterRequests(netsnmp_mib_handler *handler,
                             netsnmp_handler_registration *reginfo,
                             netsnmp_agent_request_info *reqinfo,
                             netsnmp_request_info *requests)
{
    netsnmp_request_info     *request = NULL;
    netsnmp_variable_list    *vb = NULL;
    int                      ins, rowstatus;
    oid                      subid = 0;
    PCCSP_TABLE_ENTRY        pEntry;
    struct trusted_user_entry   *pIpFilter = NULL;
    char                     ip[64] = {'\0'};
    char                     dm[128] = {'\0'};
    int                      lastIndex = -1;
    int                      index;
    int                      reqCount = 0;

    AnscTraceWarning(("%s(%d): Entering with mode %d.\n", __func__, __LINE__, reqinfo->mode));

    switch(reqinfo->mode) {
    case MODE_GET:
        for(request = requests; request != NULL; request = request->next) {

            vb = request->requestvb;
            index = vb->name[vb->name_length - 1];

            pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
            if (pEntry == NULL) {
                AnscTraceWarning(("No entry available for IpFilter\n"));
                netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
                continue;
            }
            ins = pEntry->IndexValue[0].Value.iValue;
            if(lastIndex != index) {
                snprintf(dm, sizeof(dm), HOSTS_HOST_IPADDR, ins);
                if(get_dm_value(dm, ip, sizeof(ip))) {
                    AnscTraceError(("%s(%d) %s failed.\n", __func__, __LINE__, dm));
                    netsnmp_request_set_error(request, SNMP_ERR_GENERR);
                    continue;
                }
                lastIndex = index;
                pIpFilter = lookup_trusted_user_entry(ip);
                if(pIpFilter == NULL) {
                    AnscTraceWarning(("No Entry available for IpFilter\n"));
                    netsnmp_request_set_error(request, SNMP_NOSUCHINSTANCE);
                    continue;
                }
            }
            
            get_trusted_user_entry_values(pIpFilter, request);
        }
        break;

    case MODE_SET_RESERVE1:
        for(request = requests; request != NULL; request = request->next) {

            vb = request->requestvb;
            subid = vb->name[vb->name_length - 2];

            AnscTraceWarning(("%s(%d): mode %d subid %d.\n", __func__, __LINE__, reqinfo->mode, subid));

            // Per Comcast webui: READ-ONLY fields
            if(subid == FILTER_ROWSTATUS ||
               subid == ADDRESS_START_LASTOID ||
               subid == ADDRESS_END_LASTOID) {
                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_NOTWRITABLE);
                request->processed = 1;
            }
            AnscTraceWarning(("%s(%d): exiting MODE_SET_RESERVE1.\n", __func__, __LINE__));
        }
        break;

    case MODE_SET_RESERVE2:

        // Per Comcast webui: trusted and policy need to set in a single varbing
        return set_trusted_user_entry(requests);

    case MODE_SET_ACTION:
        /* commit */
        break;
    case MODE_SET_FREE:
    case MODE_SET_COMMIT:
    case MODE_SET_UNDO:
    default:
        return SNMP_ERR_NOERROR;
    }

    AnscTraceWarning(("%s(%d): Exiting with mode %d.\n", __func__, __LINE__, reqinfo->mode));

    return SNMP_ERR_NOERROR;
}


#endif //endif CONFIG_CISCO_CCSP_PRODUCT_ARES
