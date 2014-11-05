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

#include "slap_definitions.h"
#include "slap_vco_global.h"
#include "slap_vho_exported_api.h"

#define TRUE 1
#define FALSE 0
#define HOTSPOT_DM_OPTION82_CURCUIT_ID "Device.X_COMCAST_COM_GRE.Interface.1.DHCPCircuitIDSSID"
#define HOTSPOT_DM_OPTION82_REMOTE_ID "Device.X_COMCAST_COM_GRE.Interface.1.DHCPRemoteID"
#define HOTSPOT_DM_REMOTE_ENDPOINTS "Device.X_COMCAST_COM_GRE.Interface.1.RemoteEndpoints"
#define HOTSPOT_DM_LOCAL_INTERFACES "Device.X_COMCAST_COM_GRE.Interface.1.LocalInterfaces"
#define HOTSPOT_DM_ASSOCIATE_BRIDGES "Device.X_COMCAST_COM_GRE.Interface.1.AssociatedBridges"
#define HOTSPOT_DM_WIFI_SSID "Device.WiFi.SSID.%d."
#define HOTSPOT_DM_VLAN_TAG "Device.Bridging.Bridge.%d.VLAN.1.VLANID"
#define HOTSPOT_DM_VLAN_MODE "Device.Bridging.Bridge.%d.Port.3.X_CISCO_COM_Mode"

#define CURCUIT_ID_BIT (1 << 0)
#define REMOTE_ID_BIT  (1 << 1)
#define HOTSPOT_SSID1_INS 5
#define HOTSPOT_SSID2_INS 6

#define InsertDhcpOption_lastOid 11
#define HotspotRowStatus_lastOid 12
#define PriEpAddrType_lastOid 2
#define PriEpAddr_lastOid 3
#define SecEpAddrType_lastOid 4
#define SecEpAddr_lastOid 5
#define L2ogreSourceIf_lastOid 2
#define L2ogreSourceIfEnabled_lastOid 3
#define VlanTag_lastOid 4
#define L2ogreSourceIfRowStatus_lastOid 6
#define ROWSTATUS_DESTROY 6

enum inet_address_type_e {
    INET_ADDRESS_TYPE_UNKNOWN = 0,
    INET_ADDRESS_TYPE_IPV4 = 1,
    INET_ADDRESS_TYPE_IPV6 = 2,
    INET_ADDRESS_TYPE_IPV4Z = 3,
    INET_ADDRESS_TYPE_IPV6Z = 4,
    INET_ADDRESS_TYPE_DNS  = 16
};

enum vlan_tag_cmd_e {
    GET_VLAN_TAG = 1,
    SET_VLAN_TAG = 2
};

enum wifi_if_e {
    WIFI1_0 = 1,
    WIFI1_1 = 2,
    WIFI1_2 = 3,
    WIFI1_3 = 4,
    WIFI1_4 = 5,
    WIFI1_5 = 6,
    WIFI1_6 = 7,
    WIFI1_7 = 8,
    WIFI2_0 = 9,
    WIFI2_1 = 10,
    WIFI2_2 = 11,
    WIFI2_3 = 12,
    WIFI2_4 = 13,
    WIFI2_5 = 14,
    WIFI2_6 = 15,
    WIFI2_7 = 16,
    WIFI_IF_MAX = 17
};

static const int wifi_ins[] = {
    [WIFI1_0] = 1,
    [WIFI1_1] = 3,
    [WIFI1_2] = 5,
    [WIFI1_3] = 7,
    [WIFI1_4] = 9,
    [WIFI1_5] = 11,
    [WIFI1_6] = 13,
    [WIFI1_7] = 15,
    [WIFI2_0] = 2,
    [WIFI2_1] = 4,
    [WIFI2_2] = 6,
    [WIFI2_3] = 8,
    [WIFI2_4] = 10,
    [WIFI2_5] = 12,
    [WIFI2_6] = 14,
    [WIFI2_7] = 16
};

enum vlan_mode_e {
    VLAN_TAGGING = 0,
    VLAN_PASSTHROUGH = 1
};

static const char *gVlanMode[] = {
    [VLAN_TAGGING] = "Tagging",
    [VLAN_PASSTHROUGH] = "PassThrough",
};


#define HOTSPOT_BR1_INS 3
#define HOTSPOT_BR2_INS 4 
#define HOTSPOT_SSID1_BIT (1<<0)
#define HOTSPOT_SSID2_BIT (1<<1)

static struct br_ssid_ins {
    int brIns;
    int ssidIns;
}gBrSsidIns[2] = {
    {
        .brIns = HOTSPOT_BR1_INS,
        .ssidIns = HOTSPOT_SSID1_INS
    },
    {
        .brIns = HOTSPOT_BR2_INS,
        .ssidIns = HOTSPOT_SSID2_INS
    }
};

static char *armPamDestComp = NULL;
static char *armPamDestPath = NULL;

static int cosaCommitArmPam(void)
{
    if (armPamDestComp && armPamDestPath)
        goto commit;

    if (armPamDestComp) AnscFreeMemory(armPamDestComp);
    if (armPamDestPath) AnscFreeMemory(armPamDestPath);
    armPamDestComp = armPamDestPath = NULL;

    if (!Cosa_FindDestComp(HOTSPOT_DM_OPTION82_CURCUIT_ID, &armPamDestComp, &armPamDestPath)
        || !armPamDestComp || !armPamDestPath){
        AnscTraceError(("%s: fail to find dest comp\n", __FUNCTION__));
        return FALSE;
    }
    AnscTraceWarning(("dstComp %s, dstPath %s!\n", armPamDestComp, armPamDestPath));

commit:
    Cosa_SetCommit(armPamDestComp, armPamDestPath, TRUE);
    return TRUE;
}



int getInsertDhcpOption(int *value)
{
    char strVal[64] = {'\0'};

    if (NULL == value) {
        AnscTraceWarning(("Return value pointer is null\n"));
        return FALSE;
    }

    if (get_dm_value(HOTSPOT_DM_OPTION82_CURCUIT_ID, strVal, sizeof(strVal))) {
        AnscTraceWarning(("get_dm_value: %s failed\n", HOTSPOT_DM_OPTION82_CURCUIT_ID));
        return FALSE;
    }

    if (!strcmp(strVal, "true"))
        *value |= CURCUIT_ID_BIT;
    else
        *value &= ~CURCUIT_ID_BIT;

    memset(strVal, 0, sizeof(strVal));
    if (get_dm_value(HOTSPOT_DM_OPTION82_REMOTE_ID, strVal, sizeof(strVal))) {
        AnscTraceWarning(("get_dm_value: %s failed\n", HOTSPOT_DM_OPTION82_REMOTE_ID));
        return FALSE;
    }

    if (!strcmp(strVal, "true"))
        *value |= REMOTE_ID_BIT;
    else
        *value &= ~REMOTE_ID_BIT;

    return TRUE;
    
}

int setInsertDhcpOption(int value)
{
    char curcuit[64] = {'\0'};
    char remote[64] = {'\0'};

    if (value & CURCUIT_ID_BIT)
        strncpy(curcuit, "true", strlen("true"));
    else
        strncpy(curcuit, "false", strlen("false"));

    if (value & REMOTE_ID_BIT) 
        strncpy(remote, "true", strlen("true"));
    else
        strncpy(remote, "false", strlen("false"));

    if (set_dm_value(HOTSPOT_DM_OPTION82_CURCUIT_ID, curcuit, strlen(curcuit)) ||
        set_dm_value(HOTSPOT_DM_OPTION82_REMOTE_ID, remote, strlen(remote))) {
        return FALSE;
    }

    return TRUE;
        
}

int getRemoteEpAddr(int oid, char *ip)
{
    char epAddr[256] = {'\0'};
    char *ep, *saveptr, *remoteIp[2];
    int i=0;

    if(NULL==ip) return FALSE;

    if (get_dm_value(HOTSPOT_DM_REMOTE_ENDPOINTS, epAddr, sizeof(epAddr))) {
        AnscTraceWarning(("get_dm_value: %s failed\n", HOTSPOT_DM_REMOTE_ENDPOINTS));
        return FALSE;
    }

    ep = strdup(epAddr);
    saveptr = ep;

    while ((remoteIp[i]=strsep(&saveptr, ","))!=NULL) i++;
    if ((oid==PriEpAddr_lastOid) && remoteIp[0])
        _ansc_strcpy(ip, remoteIp[0]);
    else if((oid==SecEpAddr_lastOid) && remoteIp[1]) 
        _ansc_strcpy(ip, remoteIp[1]);

    free(ep);
    return TRUE;
}

int setRemoteEpAddr(int oid, char *ip)
{
    char epAddr[256] = {'\0'};
    char *ep, *saveptr, *remoteIp[2];
    int i=0, ret=TRUE;

    if (get_dm_value(HOTSPOT_DM_REMOTE_ENDPOINTS, epAddr, sizeof(epAddr))) {
        AnscTraceWarning(("get_dm_value: %s failed\n", HOTSPOT_DM_REMOTE_ENDPOINTS));
        return FALSE;
    }

    ep = strdup(epAddr);
    saveptr = ep;

    while ((remoteIp[i]=strsep(&saveptr, ","))!=NULL) i++;

    memset(epAddr, 0, sizeof(epAddr));

    if (oid==PriEpAddr_lastOid) {
        _ansc_strcpy(epAddr, ip);
        if(remoteIp[1]) {
            _ansc_strcat(epAddr, ",");
            _ansc_strcat(epAddr, remoteIp[1]);
        }
    }else if(oid==SecEpAddr_lastOid){
        if (remoteIp[0]) {
            _ansc_strcpy(epAddr, remoteIp[0]);
            _ansc_strcat(epAddr, ",");
        }else
            _ansc_strcpy(epAddr, ",");
        _ansc_strcat(epAddr, ip);
    }

    if (set_dm_value(HOTSPOT_DM_REMOTE_ENDPOINTS, epAddr, strlen(epAddr))) 
        ret = FALSE;
		
	/* If two varbings come in one request, current custom logic will
       do set-set and commit-commit for each request with seperate dbus sessions.
       Problem is framework has been changed to limit same dm set without commit
       across sessions.
       Fix is to add commit for each set, like set-commit, set-commit.
     */
    cosaCommitArmPam();

    free(ep);
    return ret;
}

static int is_wifi_hotspot_ssid(char *localIntf, int ins)
{
    char wifiSsid[32] = {'\0'};
    
    snprintf(wifiSsid, sizeof(wifiSsid), HOTSPOT_DM_WIFI_SSID, ins);

    if (!strstr(localIntf, wifiSsid))
        return FALSE; 

    return TRUE;
}

static int hotspot_get_if_enabled(int ins, int *bEnabled)
{
    char localIntf[256] = {'\0'};
    char ssidDm[32] = {'\0'};

    snprintf(ssidDm, sizeof(ssidDm), HOTSPOT_DM_WIFI_SSID, ins);

    if(get_dm_value(HOTSPOT_DM_LOCAL_INTERFACES, localIntf, sizeof(localIntf))) {
        AnscTraceError(("Failed to get value DM %s!\n", HOTSPOT_DM_LOCAL_INTERFACES));
        return FALSE;
    }

    if (strstr(localIntf, ssidDm)) *bEnabled = 1;
    else *bEnabled = 2;

    return TRUE;
}

static int hotspot_set_if_enabled(int ins, int bEnabled)
{
    char ssidDm[32] = {'\0'};
    char localIf[256] = {'\0'};
    char *substr, *saveptr, *save, *str;
    int ifBitmask = 0, len, ifIns;
    char strVal[256] = {'\0'};

    if(get_dm_value(HOTSPOT_DM_LOCAL_INTERFACES, localIf, sizeof(localIf))) {
        AnscTraceError(("Failed to set get DM %s!\n", HOTSPOT_DM_LOCAL_INTERFACES));
        return FALSE;
    }

    str = strdup(localIf);
    save = str;

    for(substr=NULL; ; str=NULL) {
        substr = strtok_r(str, ",", &saveptr);
        if(substr == NULL) break;

        len = strlen(substr);
        if(len == 0) continue;

        if(substr[len-1] == '.') substr[len-1] = '\0';
        ifIns = substr[len-2] - '0';

        if(ifIns == HOTSPOT_SSID1_INS) 
            ifBitmask |= HOTSPOT_SSID1_BIT;
        else if(ifIns == HOTSPOT_SSID2_INS)
            ifBitmask |= HOTSPOT_SSID2_BIT;
    }

    if(save) free(save);

    if(bEnabled == 1) {
        if(ins == HOTSPOT_SSID1_INS) 
            ifBitmask |= HOTSPOT_SSID1_BIT;
        else if (ins == HOTSPOT_SSID2_INS) 
            ifBitmask |= HOTSPOT_SSID2_BIT;
    }else{
        if(ins == HOTSPOT_SSID1_INS) 
            ifBitmask &= ~HOTSPOT_SSID1_BIT;
        else if(ins == HOTSPOT_SSID2_INS) 
            ifBitmask &= ~HOTSPOT_SSID2_BIT;
    }

    if(ifBitmask & HOTSPOT_SSID1_BIT){
        snprintf(ssidDm, sizeof(ssidDm), HOTSPOT_DM_WIFI_SSID, HOTSPOT_SSID1_INS);
        _ansc_strcpy(strVal, ssidDm);
    }

    if(ifBitmask & HOTSPOT_SSID2_BIT){
        snprintf(ssidDm, sizeof(ssidDm), HOTSPOT_DM_WIFI_SSID, HOTSPOT_SSID2_INS);
        if(strlen(strVal)){
            _ansc_strcat(strVal, ",");
            _ansc_strcat(strVal, ssidDm);
        }else{
            _ansc_strcpy(strVal, ",");
            _ansc_strcat(strVal, ssidDm);
        }
    }

    if(strlen(strVal) == 0)
        _ansc_strcpy(strVal, ",");

    if(set_dm_value(HOTSPOT_DM_LOCAL_INTERFACES, strVal, strlen(strVal))) {
        AnscTraceError(("Failed to set value DM %s!\n", HOTSPOT_DM_LOCAL_INTERFACES));
        return FALSE;
    }

    return TRUE;
}

static int hotspot_vlan_tag_func(int ins, int *vlan_id, int cmd)
{
    char vlan[4], vlan_mode[16] = {'\0'};
    char *pMode;
    int ret=TRUE;
    char vlanIdDm[64] = {'\0'};
    char vlanModeDm[64] = {'\0'};
    int i, brIns=-1;
#if 0
    char assBr[2][32]={{'\0'},{'\0'}}, localIf[2][32]={{'\0'},{'\0'}};
    char *token, *brPtr, *ifPtr, *brSavePtr, *ifSavePtr;
    char brlist[256] = {'\0'};
    char localIntf[256] = {'\0'};
    char ssidDm[32] = {'\0'};

    snprintf(ssidDm, sizeof(ssidDm), HOTSPOT_DM_WIFI_SSID, ins);

    if(get_dm_value(HOTSPOT_DM_LOCAL_INTERFACES, localIntf, sizeof(localIntf))) {
        AnscTraceError(("Failed to get value DM %s!\n", HOTSPOT_DM_LOCAL_INTERFACES));
        return FALSE;
    }

    if(get_dm_value(HOTSPOT_DM_ASSOCIATE_BRIDGES, brlist, sizeof(brlist))) {
        AnscTraceError(("Failed to get value DM %s!\n", HOTSPOT_DM_ASSOCIATE_BRIDGES));
        return FALSE;
    }

    brPtr = strdup(brlist);
    brSavePtr = brPtr;
    ifPtr = strdup(localIntf);
    ifSavePtr = ifPtr;

    AnscTraceWarning(("associateBridges %s!\n", brSavePtr));
    AnscTraceWarning(("localinterfaces %s!\n", ifSavePtr));

    i = 0;
    while((token = strsep(&brSavePtr, ","))!=NULL) {
        AnscTraceWarning(("assBr[%d] %s!\n", i, token));
        _ansc_strcpy(assBr[i], token);
        i++;
    }
    i = 0;
    while((token = strsep(&ifSavePtr, ","))!=NULL) {
        printf("localIf[%d] %s!\n", i, token);
        _ansc_strcpy(localIf[i], token);
        i++;
    }

    /*we must have one match, otherwise noSuchInstance is returned */
    for (i=0; i<2; i++) {
        AnscTraceWarning(("ssidDm %s localIf[%d] %s assBr[%d] %s!\n", ssidDm, i, localIf[i], i, assBr[i]));
        if((strlen(localIf[i])) && 
           (strlen(assBr[i])) && 
           !strcmp(ssidDm, localIf[i])) {
            _ansc_strcpy(brDm, assBr[i]);
            _ansc_strcat(brDm, HOTSPOT_DM_VLAN_TAG);
            AnscTraceWarning(("VLAN TAG DM %s!\n", brDm));
            break;
        }
    }

    /*in case assocateBridges return something wrong */
    if (i>=2) {
        ret=FALSE;
        goto fini;
    }
#endif

    for(i=0; i<2; i++) {
        if (ins == gBrSsidIns[i].ssidIns){
            brIns = gBrSsidIns[i].brIns;
            break;
        }
    }

    if(i>=2) {
        ret=FALSE;
        goto fini;
    }

    if (cmd==GET_VLAN_TAG) {
        snprintf(vlanModeDm, sizeof(vlanModeDm), HOTSPOT_DM_VLAN_MODE, brIns);

        if(get_dm_value(vlanModeDm, vlan_mode, sizeof(vlan_mode))) {
            printf("Failed to get DM %s!\n", vlanModeDm);
            ret=FALSE;
            goto fini;
        }

        if (!strcmp(gVlanMode[VLAN_TAGGING], vlan_mode)) {
            *vlan_id = 0;
        }else{
            snprintf(vlanIdDm, sizeof(vlanIdDm), HOTSPOT_DM_VLAN_TAG, brIns);
            if(get_dm_value(vlanIdDm, vlan, sizeof(vlan))) {
                printf("Failed to get DM %s!\n", vlanIdDm);
                ret=FALSE;
                goto fini;
            }
            *vlan_id = atoi(vlan);
        }

    }else if (cmd==SET_VLAN_TAG) {
       if (*vlan_id != 0) {
            sprintf(vlan, "%d", *vlan_id);
            snprintf(vlanIdDm, sizeof(vlanIdDm), HOTSPOT_DM_VLAN_TAG, brIns);

            if(set_dm_value(vlanIdDm, vlan, 4)) {
                printf("Failed to set DM %s!\n", vlanIdDm);
                ret=FALSE;
                goto fini;
            }
        }

        pMode = (*vlan_id == 0) ? gVlanMode[VLAN_TAGGING] : gVlanMode[VLAN_PASSTHROUGH];
        snprintf(vlanModeDm, sizeof(vlanModeDm), HOTSPOT_DM_VLAN_MODE, brIns);

        if(set_dm_value(vlanModeDm, pMode, strlen(pMode))) {
            printf("Failed to get DM %s!\n", vlanModeDm);
            ret=FALSE;
            goto fini;
        }
    }else
        ret=FALSE;
fini:
    // free(brPtr);
    // free(ifPtr);
    return ret;
}


int
handleL2ogreBase(
    netsnmp_mib_handler             *handler,
    netsnmp_handler_registration    *reginfo,
    netsnmp_agent_request_info      *reqinfo,
    netsnmp_request_info            *requests
)
{
    netsnmp_request_info* req;
    int subid;
    int status, intval;
    int retval=SNMP_ERR_NOERROR;
    PCCSP_TABLE_ENTRY entry = NULL; 
    netsnmp_variable_list *vb = NULL;
    char ip[256] = {'\0'};

    for (req = requests; req != NULL; req = req->next) {
        vb = req->requestvb;
        subid = vb->name[vb->name_length -2];
        AnscTraceWarning(("handleL2ogreBase last 4: %d.%d.%d.%d\n", vb->name[vb->name_length-4],vb->name[vb->name_length-3],vb->name[vb->name_length-2],vb->name[vb->name_length-1]));
        
        switch (reqinfo->mode) {
            case MODE_GET:
        
            if(subid == PriEpAddr_lastOid || subid == SecEpAddr_lastOid){
                status = getRemoteEpAddr(subid, ip);   
                req->processed = 1;
            
                if (TRUE == status) {
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)ip, strlen(ip));
                    AnscTraceWarning(("handleL2ogreBase, retrieved value %s\n", ip));
                } else{
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                    AnscTraceWarning(("handleL2ogreBase failed get call subid %d\n", subid));
                }
            }
            else if (subid == PriEpAddrType_lastOid || subid == SecEpAddrType_lastOid) {
                intval = INET_ADDRESS_TYPE_IPV4;
                snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&intval, 4);
                req->processed = 1;
            }
            break;

            case MODE_SET_RESERVE1:
            /* sanity check */
            if (subid == PriEpAddr_lastOid || subid == SecEpAddr_lastOid) {
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_OCTET_STR))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, retval);
                }
                
                req->processed = 1;
            }else if(subid == PriEpAddrType_lastOid || subid == SecEpAddrType_lastOid){ 
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, retval);
                }else if ( *(vb->val.integer) != INET_ADDRESS_TYPE_IPV4 && 
                           *(vb->val.integer) != INET_ADDRESS_TYPE_IPV6 &&
                           *(vb->val.integer) != INET_ADDRESS_TYPE_DNS) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;
                }
                
                req->processed = 1;
            } 
            /* request->processed will be reset in every step by netsnmp_call_handlers */
            break;

            case MODE_SET_RESERVE2:
            /* set value to backend with no commit */
                if (subid == PriEpAddr_lastOid || subid == SecEpAddr_lastOid) {
                    status = setRemoteEpAddr(subid, vb->val.string);
                    req->processed = 1;
            
                    if (FALSE == status) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                        retval = SNMP_ERR_GENERR;
                    } 
                }
                else if(subid == PriEpAddrType_lastOid || subid == SecEpAddrType_lastOid){
                    req->processed = 1;
                }
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
                netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                return SNMP_ERR_GENERR;
        }
    }
    return SNMP_ERR_NOERROR;
}

int
handleHotspotIf(
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
        subid = vb->name[vb->name_length -2];
        AnscTraceWarning(("HotspotIf last 4: %d.%d.%d.%d\n", vb->name[vb->name_length-4],vb->name[vb->name_length-3],vb->name[vb->name_length-2],vb->name[vb->name_length-1]));
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceWarning(("No entry found for HotspotIf\n"));
            continue;
        }

        index = entry->IndexValue[0].Value.iValue;
        #if 0
        if (is_wifi_hotspot_ssid(localIntf, index) == 0) {
        #else
        if (index != HOTSPOT_SSID1_INS) {
        #endif
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceWarning(("Instance number %d are not for Hotspot SSID\n", index));
            continue;
        }
        
        switch (reqinfo->mode) {
            case MODE_GET:
        
            intval = 0;
            if(subid == InsertDhcpOption_lastOid){
                status = getInsertDhcpOption(&intval);   
                req->processed = 1;
            
                if (TRUE == status) {
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_UNSIGNED, (u_char *)&intval, sizeof(intval));
                    AnscTraceWarning(("HotspotIf, retrieved value %d\n", intval));
                } else{
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                    AnscTraceWarning(("HotspotIf failed get call subid %d\n", subid));
                }
            }
            break;

            case MODE_SET_RESERVE1:
            /* sanity check */
            if (subid == InsertDhcpOption_lastOid) {
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_UNSIGNED))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, retval);
                } else if ( *(vb->val.integer) > 7 || *(vb->val.integer) < 0) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;
                }
                
                req->processed = 1;
            } 
            /* request->processed will be reset in every step by netsnmp_call_handlers */
            break;

            case MODE_SET_RESERVE2:
            /* set value to backend with no commit */
                if(subid == InsertDhcpOption_lastOid) {
                    status = setInsertDhcpOption(*(vb->val.integer));
                    req->processed = 1;
            
                    if (FALSE == status) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                        retval = SNMP_ERR_GENERR;
                    } 
                }else if (subid == HotspotRowStatus_lastOid) {
                    req->processed = 1;
                    netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                    retval = SNMP_ERR_GENERR;
                }
                break;

            case MODE_SET_ACTION:
                cosaCommitArmPam();
                /* commit */
                break;
            case MODE_SET_FREE:   
                break;
            case MODE_SET_COMMIT:
            case MODE_SET_UNDO:
                /* nothing */
                break;
            default:
                netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                return SNMP_ERR_GENERR;
        }
    }
    return SNMP_ERR_NOERROR;
}

int
handleL2ogreSourceIf(
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
    int index, i;

    for (req = requests; req != NULL; req = req->next) {
        vb = req->requestvb;
        subid = vb->name[vb->name_length -2];
        AnscTraceWarning(("L2ogreSourceIf last 4: %d.%d.%d.%d\n", vb->name[vb->name_length-4],vb->name[vb->name_length-3],vb->name[vb->name_length-2],vb->name[vb->name_length-1]));
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceWarning(("No entry found for L2ogreSourceIf\n"));
            continue;
        }        

        index = entry->IndexValue[0].Value.iValue;
        #if 0
        if (is_wifi_hotspot_ssid(localIntf, index) == 0) {
        #else
        if (index != HOTSPOT_SSID1_INS && index != HOTSPOT_SSID2_INS) {
        #endif
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceWarning(("Instance number %d are not for Hotspot SSID\n", index));
            continue;
        }

        switch (reqinfo->mode) {
            case MODE_GET:
        
            intval = 0;
            if(subid == VlanTag_lastOid){
                status = hotspot_vlan_tag_func(index, &intval, GET_VLAN_TAG);   
                req->processed = 1;
            
                if (TRUE == status) {
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&intval, sizeof(intval));
                    AnscTraceWarning(("L2ogreSourceIf, retrieved value %d\n", intval));
                } else{
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                    AnscTraceWarning(("L2ogreSourceIf failed get call subid %d\n", subid));
                }
            }else if (subid == L2ogreSourceIf_lastOid) {
                req->processed = 1;
                for (i=1;i<WIFI_IF_MAX;i++) {
                    if (index == wifi_ins[i]) break;
                }
                if(i>=WIFI_IF_MAX) netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                else snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&i, sizeof(int));
            }else if (subid == L2ogreSourceIfEnabled_lastOid) {
                status = hotspot_get_if_enabled(index, &intval);
                req->processed = 1;

                if (TRUE == status) {
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&intval, sizeof(intval));
                    AnscTraceWarning(("L2ogreSourceIfEnabled, retrieved value %d\n", intval));
                } else{
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                    AnscTraceWarning(("L2ogreSourceIfEnabled failed get call subid %d\n", subid));
                }
            }
            break;

            case MODE_SET_RESERVE1:
            /* sanity check */
            if ((subid == VlanTag_lastOid) || (subid == L2ogreSourceIf_lastOid)) {
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, retval);
                } 
                
                req->processed = 1;
                /* request->processed will be reset in every step by netsnmp_call_handlers */
            }else if (subid == L2ogreSourceIfEnabled_lastOid) {
                if (*(vb->val.integer) != 1 && *(vb->val.integer) != 2) {
                    netsnmp_request_set_error(req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;
                }
            }
            break;

            case MODE_SET_RESERVE2:
                /* set value to backend with no commit */
                if(subid == VlanTag_lastOid) {
                    status = hotspot_vlan_tag_func(index, (vb->val.integer), SET_VLAN_TAG);
                    req->processed = 1;
            
                    if (FALSE == status) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                        retval = SNMP_ERR_GENERR;
                    } 
                }else if(subid == L2ogreSourceIf_lastOid){
                    req->processed = 1;
                    /*currently do nothing here*/
                }else if (subid == L2ogreSourceIfRowStatus_lastOid) {
                    req->processed = 1;
                    netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                    retval = SNMP_ERR_GENERR;
                }else if (subid == L2ogreSourceIfEnabled_lastOid) {
                    status = hotspot_set_if_enabled(index, *(vb->val.integer));
                    req->processed = 1;

                    if (FALSE == status) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                        retval = SNMP_ERR_GENERR;
                    }
                }
                break;

            case MODE_SET_ACTION:
                cosaCommitArmPam();
                /* commit */
                break;
            case MODE_SET_FREE:   
                break;
            case MODE_SET_COMMIT:
            case MODE_SET_UNDO:
                /* nothing */
                break;
            default:
                netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                return SNMP_ERR_GENERR;
        }
    }

    return SNMP_ERR_NOERROR;
}

int
handleWifiAssocatedDevice(
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
        subid = vb->name[vb->name_length - 3];     /* we got two indexes */
        AnscTraceWarning(("WifiAssociatedDevice last 4: %d.%d.%d.%d!\n", vb->name[vb->name_length-4],vb->name[vb->name_length-3],vb->name[vb->name_length-2],vb->name[vb->name_length-1]));
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceWarning(("No entry found for WifiAssociatedDevice!\n"));
            continue;
        }
        /* currently the SSID instance numbers are staticlly 5 & 6 for Hotspot */
        index = entry->IndexValue[0].Value.iValue;  /* first of two indexes */
        if (index != HOTSPOT_SSID1_INS && index != HOTSPOT_SSID2_INS) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceWarning(("Instance number %d are not for Hotspot SSID\n", index));
            continue;
        }
    }

    return SNMP_ERR_NOERROR;
}

/* end of file */
