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

#include <string.h>
#include "ansc_platform.h"
#include "cosa_api.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "ccsp_snmp_common.h"
#include "ccsp_mib_definitions.h"
#include <time.h>

#define WIFI_DM_OBJ          "Device.WiFi."
#define WIFI_DM_BSSENABLE    "Device.WiFi.SSID.%d.Enable"
#define WIFI_DM_APPLY        "Device.WiFi.Radio.%d.X_CISCO_COM_ApplySetting"
#define WIFI_DM_MACF_ENABLE  "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MACFilter.Enable"
#define WIFI_DM_MACF_ASBL    "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MACFilter.FilterAsBlackList"
#define WIFI_DM_CHANNEL      "Device.WiFi.Radio.%d.Channel"
#define WIFI_DM_AUTOCHAN     "Device.WiFi.Radio.%d.AutoChannelEnable"
#define WIFI_DM_ADVERTISE    "Device.WiFi.AccessPoint.%d.SSIDAdvertisementEnabled"
#define WIFI_DM_RADIO_ENABLE "Device.WiFi.Radio.%d.Enable"
#define WIFI_DM_RADIO_COUNTRY "Device.WiFi.Radio.%d.RegulatoryDomain"
#define WIFI_DM_WMM_ENABLE   "Device.WiFi.AccessPoint.%d.WMMEnable"
#define WIFI_DM_WMM_UAPSD_ENABLE   "Device.WiFi.AccessPoint.%d.UAPSDEnable"
#define WIFI_DM_WMM_NOACK    "Device.WiFi.AccessPoint.%d.X_CISCO_COM_WmmNoAck"
#define WIFI_DM_MCASTRATE    "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MulticastRate"
#define WIFI_DM_OPERSTD      "Device.WiFi.Radio.%d.OperatingStandards"
#define WIFI_DM_NPHYRATE     "Device.WiFi.Radio.%d.MCS"
#define WIFI_DM_PSK          "Device.WiFi.AccessPoint.%d.Security.X_COMCAST-COM_KeyPassphrase"
#define WIFI_DM_NUMBER_APS   "Device.WiFi.AccessPointNumberOfEntries"
#define WIFI_DM_BSSHOTSPOT  "Device.WiFi.AccessPoint.%d.X_CISCO_COM_BssHotSpot"
#define WIFI_DM_BSSISOLATIONENABLE"Device.WiFi.AccessPoint.%d.IsolationEnable"
#define WIFI_DM_RADIO_USERCONTROL "Device.WiFi.Radio.%d.X_CISCO_COM_MbssUserControl" 
#define WIFI_DM_RADIO_ADMINCONTROL "Device.WiFi.Radio.%d.X_CISCO_COM_AdminControl"
#define WIFI_DM_BSSID         "Device.WiFi.SSID.%d.BSSID"
#define WIFI_DM_SSID          "Device.WiFi.SSID.%d.SSID"
#define WIFI_DM_WPS           "Device.WiFi.AccessPoint.%d.WPS.Enable"
#define WIFI_DM_WPSTIME       "Device.WiFi.AccessPoint.%d.WPS.X_CISCO_COM_WpsPushButton"
#define WIFI_DM_DEFAULT_SSID  "Device.WiFi.SSID.%d.X_COMCAST-COM_DefaultSSID"
#define WIFI_DM_DEFAULT_PSK   "Device.WiFi.AccessPoint.%d.Security.X_COMCAST-COM_DefaultKeyPassphrase"

#define MAX_APS_PER_RADIO 16

#define NOT_IMPLEMENTED -2 

static const int saRgDot11BssId_subid = 1;
static const int saRgDot11BssSsid_subid = 3;
static const int saRgDot11BssEnable_subid = 2;
static const int saRgDot11BssSecurityMode_subid = 4;
static const int saRgDot11BssMaxNumSta_subid = 11;
static const int saRgDot11BssUserStatus_subid = 13;
static const int saRgDot11BssAccessMode_subid = 6;
static const int saRgDot11BssClosedNetwork_subid = 5;
static const int saRgDot11BssHotSpot_subid = 14;
static const int saRgDot11BssIsolationEnable_subid = 15;
static const int saRgDot11ExtOperMode_subid =1 ;
static const int saRgDot11ExtCurrentChannel_subid = 3; 
static const int saRgDot11ExtCountry_subid = 13;
static const int saRgDot11ExtMbssUserControl_subid = 15;
static const int saRgDot11ExtMbssAdminControl_subid = 17;
static const int saRgDot11ExtWmm_subid = 20;
static const int saRgDot11ExtWmmNoAck_subid = 21;
static const int saRgDot11ExtMulticastRate_subid = 22;
static const int saRgDot11nExtMode_subid = 1;
static const int saRgDot11nExtPhyRate_subid = 2;
static const int saRgDot11WpaPreSharedKey_subid = 2;
static const int saRgDot11BSSDefaultSSID_subid = 16;
static const int saRgDot11WpaDefaultPreSharedKey_subid = 4;

static char *dstComp, *dstPath; /* cache */

static void* commitThreadHandle = NULL;
pthread_mutex_t commitMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t commitCond = PTHREAD_COND_INITIALIZER;
static int bPendingCommit = 0;

static BOOL FindWifiDestComp(void);

typedef enum Mode {
    kAuto = 1, // b/g/n or a/n
    kNOff = 2,
    kNOnly = 3,
    kBMask = 16,
    kGMask = 32,
    kAMask = 64,             
    kNMask = 128,
    kACMask = 256
} eMode;

//TODO: Make this dynamic
//SA_CUSTOM_COMCAST
static int isRadio5GHz(int entry) {
    if (entry == 1) {
        return 0;
    } else {
        return 1;
    }
}

static int getNumAPs( ) {
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[80];
    char* name = (char *)mystring;
    
    AnscTraceError(("get number of APs \n" ));
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    // return 4;

    snprintf(name, sizeof(mystring), WIFI_DM_NUMBER_APS);
    printf("%s: DML command %s \n", __FUNCTION__, name);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    printf("%s: DML command %s returned %s \n",__FUNCTION__,  name, valStr[0]->parameterValue);
    retval = _ansc_atoi(valStr[0]->parameterValue);
    
    Cosa_FreeParamValues(nval, valStr);
    
    CcspTraceInfo(("%s: Get number of APs returning %d \n",__FUNCTION__, retval ));

    return retval;
}
/*
 * PARAMS
 * radioInst - The Device.WiFi.Radio. instance number
 * apInsts - a passed in array of integers to be filled with the AccessPoint instance numbers associated with the passed in radio instance.
 * aps - IN/OUT - in param specifies the size of apInsts, out param specifies the number of filled entries.
 * 
 * Returns 
 * 0 - success or
 * ccsp error code
 */
static int SetAllAPsonRadio(int radioInst, parameterValStruct_t valStr[], char* namestrings, int strSize, int* aps, const char* dmFormat, char* value, int type) {
    int i = 0;
    int offset = 0;

    // Radio 1 has odd AP instance numbers 1,3,5,... and Radio 2 has even numbers.  Currently supporting 2 AP per radio
    int numAPs = getNumAPs();

    if (numAPs <= 0) {
        return -1;
    }

    *aps = numAPs/2;
 #if 0
    for(i = 0; i < *aps; i++) {
        offset = (i == 0) ? 0 : (i*strSize);
        valStr[i].parameterValue = value;
        valStr[i].parameterName = &namestrings[offset];
        sprintf(valStr[i].parameterName, dmFormat, radioInst+(i*2));
        valStr[i].type = type;
    }
#endif
        valStr[0].parameterValue = value;
        valStr[0].parameterName = &namestrings[0];
        sprintf(valStr[0].parameterName, dmFormat, radioInst);
        valStr[0].type = type;
    return 0;
}

static BOOL FindWifiDestComp(void)
{
    if (dstComp && dstPath)
        return TRUE;

    if (dstComp)
        AnscFreeMemory(dstComp);
    if (dstPath)
        AnscFreeMemory(dstPath);
    dstComp = dstPath = NULL;

    if (!Cosa_FindDestComp(WIFI_DM_OBJ, &dstComp, &dstPath)
            || !dstComp || !dstPath)
    {
        CcspTraceError(("%s: fail to find dest comp\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

static int applyDot11Settings(int val) {
	int retval;
	
    parameterValStruct_t valStr[2];
    
    char str[4][100];
    valStr[0].parameterName=str[0];
    valStr[0].parameterValue=str[1];
    valStr[1].parameterName=str[2];
    valStr[1].parameterValue=str[3];
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    if (val != 1)
        val = 0;

    sprintf(valStr[0].parameterName, WIFI_DM_APPLY, 1);
    sprintf(valStr[0].parameterValue, "%s", val ? "true" : "false");
    valStr[0].type = ccsp_boolean;

    sprintf(valStr[1].parameterName, WIFI_DM_APPLY, 2);
    sprintf(valStr[1].parameterValue, "%s", val ? "true" : "false");
    valStr[1].type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 2))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, WIFI_DM_APPLY));
        return -1;
    }

    return 0;
}

static void* wifiCommitThread(void* arg) {
    while(1) {
        pthread_mutex_lock(&commitMutex);
        while(!bPendingCommit)
            pthread_cond_wait(&commitCond, &commitMutex);
        
        bPendingCommit = 0;
        pthread_mutex_unlock(&commitMutex);
        Cosa_SetCommit(dstComp, dstPath, TRUE);
    }
}

static int getWps(PCCSP_TABLE_ENTRY entry)
{
    parameterValStruct_t **valStr;
    int nval, retval;
    char str[80];
    char * name = (char*) str;

    /*Fetching*/
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    snprintf(str, sizeof(str),WIFI_DM_WPSTIME,1);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval == 0)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    // if return val is 0 WPS is off on the 2.4 GHz Primary SSID, check the 5 GHz Primary SSID
    retval = atoi(valStr[0]->parameterValue);
    if (retval == 0) {
        snprintf(str, sizeof(str),WIFI_DM_WPSTIME,2);
        if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
        {
            CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));        
            return -1;
        }
        if (nval == 0)
        {
            CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
            return -1;
        }
        retval = atoi(valStr[0]->parameterValue);
    }
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

int setWps(PCCSP_TABLE_ENTRY entry, int wpsTime)
{
    int retval;
	
	parameterValStruct_t valStr;
    char str[2][100];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    // Turn off Wps if wpsTime is 0, else enable it
    sprintf(valStr.parameterName, WIFI_DM_WPS,1);
    sprintf(valStr.parameterValue, "%s",  (wpsTime == 0) ? "false": "true");
    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    sprintf(valStr.parameterName, WIFI_DM_WPS,2);
    sprintf(valStr.parameterValue, "%s",  (wpsTime == 0) ? "false": "true");
    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    sprintf(valStr.parameterName, WIFI_DM_WPSTIME,1);
    sprintf(valStr.parameterValue, "%d", wpsTime); 
    valStr.type = ccsp_int;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    sprintf(valStr.parameterName, WIFI_DM_WPSTIME,2);
    sprintf(valStr.parameterValue, "%d", wpsTime); 
    valStr.type = ccsp_int;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

int
handleDot11Wps(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
)
{
 int value;
 int ret;
netsnmp_request_info* req;
    PCCSP_TABLE_ENTRY entry = NULL;

 //TODO Check inputs, return proper error codes.
 switch (reqinfo->mode) {
    case MODE_GET:
        for (req = requests; req != NULL; req = req->next)
        {
            entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
            value = getWps(entry);
            snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char*)&value, sizeof(value));
            req->processed = 1;
        }
        break;

    case MODE_SET_RESERVE1:
        /* sanity check */
        for (req = requests; req != NULL; req = req->next)
        {
            ret = netsnmp_check_vb_type(req->requestvb, ASN_INTEGER);
            if (ret != SNMP_ERR_NOERROR)
                netsnmp_set_request_error(reqinfo, req, ret);
            req->processed = 1;     /* request->processed will be reset in every step by netsnmp_call_handlers */
            break;
            
        }
        break;

    case MODE_SET_RESERVE2:
        /* set value to backend with no commit */
        for (req = requests; req != NULL; req = req->next)
        {
            setWps(entry, *(req->requestvb->val.integer));
            req->processed = 1;
        }
 
        break;

    case MODE_SET_FREE:
        break;
    case MODE_SET_ACTION:
        break;
    case MODE_SET_COMMIT:
        /* 
         * Since cache is skipped, There is no way for plugin framework to know the CcspComp and CcspPath
         * Custom logic will handle the commit operation.
         */
        if(FindWifiDestComp() == TRUE)
            Cosa_SetCommit(dstComp, dstPath, TRUE);
        break;

    case MODE_SET_UNDO:
        break;

    default:
        netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;

}

int
handleDot11ApplySettings(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
){
 int value = 2;
 int ret;
netsnmp_request_info* req;
 //TODO Check inputs, return proper error codes.
 switch (reqinfo->mode) {
    case MODE_GET:
        for (req = requests; req != NULL; req = req->next)
        {
            value =2;
            snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char*)&value, sizeof(value));
            req->processed = 1;
        }
        break;

    case MODE_SET_RESERVE1:
        /* sanity check */
        for (req = requests; req != NULL; req = req->next)
        {
            ret = netsnmp_check_vb_type(req->requestvb, ASN_INTEGER);
            if (ret != SNMP_ERR_NOERROR)
                netsnmp_set_request_error(reqinfo, req, ret);
            req->processed = 1;     /* request->processed will be reset in every step by netsnmp_call_handlers */
            break;
            
        }
        break;

    case MODE_SET_RESERVE2:
        /* set value to backend with no commit */
        for (req = requests; req != NULL; req = req->next)
        {
            if(applyDot11Settings(*(req->requestvb->val.integer)))
                return SNMP_ERR_GENERR;
            req->processed = 1;
        }
 
        break;

    case MODE_SET_ACTION:
        /* commit */
        AnscTraceWarning(("Dot11ApplySettings SET_ACTION\n"));
        if (commitThreadHandle == NULL) {
            commitThreadHandle = AnscCreateTask(wifiCommitThread, USER_DEFAULT_TASK_STACK_SIZE, USER_DEFAULT_TASK_PRIORITY, NULL, "SNMPWifiCustomCommitThread");
            CcspTraceWarning(("Spawned Dot11ApplySettings background thread\n"));
        }
        pthread_mutex_lock(&commitMutex);
        bPendingCommit = 1;
        pthread_cond_signal(&commitCond);
        pthread_mutex_unlock(&commitMutex);
        //req->processed = 1;
        
        break;

    case MODE_SET_FREE:
        
        //break;

    case MODE_SET_COMMIT:
    case MODE_SET_UNDO:
        /*for (req = requests; req != NULL; req = req->next)
        {
            req->processed = 1;
        }*/
        break;

    default:
        netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;

}

static int getBssEnable(PCCSP_TABLE_ENTRY entry) {
    parameterValStruct_t **valStr, **valStr2;
    int nval, retval, nval2;
    char mystring[30];
    char* name = (char *)mystring;
    
    CcspTraceInfo(("getBssEnable called on entry: %d (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp();
	
    CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    snprintf(name, sizeof(mystring), WIFI_DM_BSSENABLE, entry->IndexValue[0].Value.uValue);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if(entry->IndexValue[0].Value.uValue % 2) 
        snprintf(name, sizeof(mystring), WIFI_DM_RADIO_ENABLE, 1);
    else
        snprintf(name, sizeof(mystring), WIFI_DM_RADIO_ENABLE, 2);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval2, &valStr2))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval<1 || nval2<1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    retval = _ansc_strncmp("false", valStr[0]->parameterValue, 6)&&_ansc_strncmp("false", valStr2[0]->parameterValue, 6) ? 1 : 2;
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setBssEnable(PCCSP_TABLE_ENTRY entry, int value) {
    parameterValStruct_t valStr;
	int retval;
    char str[2][100];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    // Not supporting enableOnline(3) for GA 1.2
    if (value <  1 || value > 2)
        return -1;

    sprintf(valStr.parameterName, WIFI_DM_BSSENABLE, entry->IndexValue[0].Value.uValue);
    sprintf(valStr.parameterValue, "%s", value == 1 ? "true" : "false");
    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

static int getBssAccessMode(PCCSP_TABLE_ENTRY entry) {
    parameterValStruct_t **valStr;
    int nval, retval;
    char str[2][100];
    char* name[2] = {(char*) str[0], (char*) str[1]};
    
    CcspTraceInfo(("getBssAccessMode called on entry: %d\n", entry->IndexValue[0].Value.uValue));
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    snprintf(str[0], sizeof(str[0]),WIFI_DM_MACF_ENABLE,entry->IndexValue[0].Value.uValue);
    snprintf(str[1], sizeof(str[1]),WIFI_DM_MACF_ASBL,entry->IndexValue[0].Value.uValue);

    if (!Cosa_GetParamValues(dstComp, dstPath, name, 2, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s or %s\n", __FUNCTION__, name[0], name[1]));
        return -1;
    }

    if (nval < 2)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    
    if(strncmp("true", valStr[0]->parameterValue, 5)==0) {
        /*If mac filter is enabled, check if the list is a blacklist*/
        if (strncmp("true", valStr[1]->parameterValue, 5)==0) {
            /*Blacklist*/
            retval = 2;
        } else {
            retval = 1;
        }
    } else {
        retval = 0;
    }
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setBssAccessMode(PCCSP_TABLE_ENTRY entry, int value) {
    parameterValStruct_t valStr[2];
	int retval;
    char str[4][80];
    valStr[0].parameterName = str[0];
    valStr[0].parameterValue = str[1];
    valStr[1].parameterName = str[2];
    valStr[1].parameterValue = str[3];
    int valCnt =1;
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    /*snprintf(name[0], sizeof(name[0]),WIFI_DM_MACF_ENABLE,entry->IndexValue[0].Value.uValue);
    snprintf(name[1], sizeof(name[1]),WIFI_DM_MACF_ASBL,entry->IndexValue[0].Value.uValue);*/
    sprintf(valStr[0].parameterName, WIFI_DM_MACF_ENABLE, entry->IndexValue[0].Value.uValue);
    valStr[0].type = ccsp_boolean;
    if (value == 0) {
        /*allowAny*/
        sprintf(valStr[0].parameterValue, "%s", "false");
    } else {
        /*Mac filter enabled*/
        sprintf(valStr[0].parameterValue, "%s", "true");
        sprintf(valStr[1].parameterName, WIFI_DM_MACF_ASBL, entry->IndexValue[0].Value.uValue);
        valStr[1].type = ccsp_boolean;
        valCnt = 2;
        if (value == 1) {
            /*allowList*/
            sprintf(valStr[1].parameterValue, "%s", "false");
        } else {
            /*denyList*/
            sprintf(valStr[1].parameterValue, "%s", "true");
        }
    }

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, valCnt))
    {
        CcspTraceError(("%s: fail to set: %s or %s\n", __FUNCTION__, valStr[0].parameterName, valStr[1].parameterName));
        return -1;
    }

    return 0;
}

static int getBssClosedNetwork(PCCSP_TABLE_ENTRY entry) {
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[100];
    char* name = (char *)mystring;
    
    CcspTraceInfo(("getBssClosedNetwork called on entry: %d (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    snprintf(name, sizeof(mystring), WIFI_DM_ADVERTISE, entry->IndexValue[0].Value.uValue);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    /*Invert the truth value, per the syntax of the MIB*/
    retval = _ansc_strncmp("true", valStr[0]->parameterValue, 5) ? 1 : 2;
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setBssClosedNetwork(PCCSP_TABLE_ENTRY entry, int value) {
    parameterValStruct_t valStr;
	int retval;
    char str[2][100];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    if (value != 1)
        value = 2;

    sprintf(valStr.parameterName, WIFI_DM_ADVERTISE, entry->IndexValue[0].Value.uValue);
    sprintf(valStr.parameterValue, "%s", value == 2 ? "true" : "false");
    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

static int getBssHotSpot(PCCSP_TABLE_ENTRY entry) {
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[100];
    char* name = (char *)mystring;
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    snprintf(name, sizeof(mystring), WIFI_DM_BSSHOTSPOT, entry->IndexValue[0].Value.uValue);
    CcspTraceInfo(("%s: called on entry: %d %s(%d)\n", __func__, entry->IndexValue[0].Value.uValue, mystring, sizeof(mystring)));
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    retval = _ansc_strncmp("false", valStr[0]->parameterValue, 5) ? 1 : 2;
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setBssHotSpot(PCCSP_TABLE_ENTRY entry, int value) {
    parameterValStruct_t valStr;
	int retval;
    char str[2][100];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    if (value != 1)
        value = 2;

    sprintf(valStr.parameterName, WIFI_DM_BSSHOTSPOT, entry->IndexValue[0].Value.uValue);
    sprintf(valStr.parameterValue, "%s", value == 1 ? "true" : "false");
    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}
static int getBssIsolationEnable(PCCSP_TABLE_ENTRY entry) {
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[100];
    char* name = (char *)mystring;
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    snprintf(name, sizeof(mystring), WIFI_DM_BSSISOLATIONENABLE, entry->IndexValue[0].Value.uValue);
    CcspTraceInfo(("%s: called on entry: %d %s(%d)\n", __func__, entry->IndexValue[0].Value.uValue, mystring, sizeof(mystring)));
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    retval = _ansc_strncmp("false", valStr[0]->parameterValue, 5) ? 1 : 0;
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setBssIsolationEnable(PCCSP_TABLE_ENTRY entry, int value) {
    parameterValStruct_t valStr;
	int retval;
    char str[2][100];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    if (value != 1)
        value = 0;

    sprintf(valStr.parameterName, WIFI_DM_BSSISOLATIONENABLE, entry->IndexValue[0].Value.uValue);
    sprintf(valStr.parameterValue, "%s", value == 1 ? "true" : "false");
    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

/* saRgDot11BssTable custom cache handler */
#define ARRAY_SIZE(x) ((unsigned)sizeof((x))/sizeof((x)[0]))

struct dot11_data_s {
    int mib_index;
    CCSP_TABLE_ENTRY entry;
};

enum wifi_if_e {
    WIFI_UNKNOWN = 0,
    WIFI1_1 = 1,
    WIFI2_1 = 2,
    WIFI1_2 = 3,
    WIFI2_2 = 4,
    WIFI1_3 = 5,
    WIFI2_3 = 6,
    WIFI1_4 = 7,
    WIFI2_4 = 8,
    WIFI1_5 = 9,
    WIFI2_5 = 10,
    WIFI1_6 = 11,
    WIFI2_6 = 12,
    WIFI1_7 = 13,
    WIFI2_7 = 14,
    WIFI1_8 = 15,
    WIFI2_8 = 16,
};

static struct dot11_data_s gDot11Info[] = {
    [WIFI_UNKNOWN] = {
        .mib_index = -1,
    },
    [WIFI1_1] = {
        .mib_index = 10001,
    },
    [WIFI2_1] = {
        .mib_index = 10101,
    },
    [WIFI1_2] = {
        .mib_index = 10002,
    },
    [WIFI2_2] = {
        .mib_index = 10102,
    },
    [WIFI1_3] = {
        .mib_index = 10003,
    },
    [WIFI2_3] = {
        .mib_index = 10103,
    },
    [WIFI1_4] = {
        .mib_index = 10004,
    },
    [WIFI2_4] = {
        .mib_index = 10104,
    },
    [WIFI1_5] = {
        .mib_index = 10005,
    },
    [WIFI2_5] = {
        .mib_index = 10105,
    },
    [WIFI1_6] = {
        .mib_index = 10006,
    },
    [WIFI2_6] = {
        .mib_index = 10106,
    },
    [WIFI1_7] = {
        .mib_index = 10007,
    },
    [WIFI2_7] = {
        .mib_index = 10107,
    },
    [WIFI1_8] = {
        .mib_index = 10008,
    },
    [WIFI2_8] = {
        .mib_index = 10108,
    },
};


static int mac_string_to_array(const char *pStr, unsigned char array[6])
{
    int tmp[6],n,i;
	if(pStr == NULL)
		return -1;
		
    memset(array,0,6);
    n = sscanf(pStr,"%02x:%02x:%02x:%02x:%02x:%02x",&tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5]);
    if(n==6){
        for(i=0;i<n;i++)
            array[i] = (unsigned char)tmp[i];
        return 0;
    }

    return -1;
}


static int getBssid(PCCSP_TABLE_ENTRY pEntry, char *macArray)
{
    char dmStr[128] = {'\0'};
    char mac[18] = {'\0'};

    if(!macArray)
        return -1;

    snprintf(dmStr, sizeof(dmStr), WIFI_DM_BSSID, pEntry->IndexValue[0].Value.uValue);
    if(get_dm_value(dmStr, mac, 18))
        return -1;

    return mac_string_to_array(mac, macArray);

}

static int getDefaultSsid(PCCSP_TABLE_ENTRY pEntry, char *defaultssid)
{
    char dmStr[128] = {'\0'};

    if(!defaultssid)
        return -1;

    snprintf(dmStr, sizeof(dmStr), WIFI_DM_DEFAULT_SSID, pEntry->IndexValue[0].Value.uValue);
    if(get_dm_value(dmStr, defaultssid, 33))
       return -1;
    	

	

    return 0; 
}
static int getSsid(PCCSP_TABLE_ENTRY pEntry, char *ssid)
{
    char dmStr[128] = {'\0'};

    if(!ssid)
        return -1;

    snprintf(dmStr, sizeof(dmStr), WIFI_DM_SSID, pEntry->IndexValue[0].Value.uValue);
    if(get_dm_value(dmStr, ssid, 33))
        return -1;

    return 0; 
}

static int setBssSsid(PCCSP_TABLE_ENTRY pEntry, const char *ssid)
{
    parameterValStruct_t valStr;
	int retval;
    char str[2][100];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    sprintf(valStr.parameterName, WIFI_DM_SSID, pEntry->IndexValue[0].Value.uValue);
    sprintf(valStr.parameterValue, "%s", ssid);
    valStr.type = ccsp_string;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

#define WIFI_DM_BSS_SECURITY_MODE "Device.WiFi.AccessPoint.%d.Security.ModeEnabled"
#define WIFI_DM_BSS_ENCRYPTION "Device.WiFi.AccessPoint.%d.Security.X_CISCO_COM_EncryptionMethod"

static int getBssSecurityMode(PCCSP_TABLE_ENTRY pEntry)
{
    char dmStr[128] = {'\0'};
    char dmValue[64] = {'\0'};
    
    if(!pEntry)
        return -1;

    snprintf(dmStr, sizeof(dmStr), WIFI_DM_BSS_SECURITY_MODE, pEntry->IndexValue[0].Value.uValue);

    if(get_dm_value(dmStr, dmValue, sizeof(dmValue)))
        return -1;

#ifdef _XB6_PRODUCT_REQ_
	if(!strcmp(dmValue, "None"))
        return 0;
	else if (!strcmp(dmValue, "WPA2-Personal"))
        return 3;
    else if (!strcmp(dmValue, "WPA2-Enterprise"))
        return 5;
	else
        return 0;
#else
    if(!strcmp(dmValue, "None"))
        return 0;
    else if(!strcmp(dmValue, "WEP-128"))
        return 1;
    else if (!strcmp(dmValue, "WEP-64"))
        return 1;
    else if (!strcmp(dmValue, "WPA-Personal"))
        return 2;
    else if (!strcmp(dmValue, "WPA2-Personal"))
        return 3;
     else if (!strcmp(dmValue, "WPA2-Enterprise"))
        return 5;
    else if (!strcmp(dmValue, "WPA-WPA2-Personal"))
        return 7;
    else if (!strcmp(dmValue, "WPA-WPA2-Enterprise"))
        return 8;
    else
        return 0;
#endif
}

static int setBssSecurityMode(PCCSP_TABLE_ENTRY pEntry, int mode)
{
    parameterValStruct_t valStr[2];
	int retval;
    char str[4][100];
    valStr[0].parameterName=str[0];
    valStr[0].parameterValue=str[1];
    valStr[1].parameterName = str[2];
    valStr[1].parameterValue = str[3];
    int valCnt =1;
    unsigned int algor = 2;
    char modeStr[64] = {'\0'};
    
    switch(mode){
#ifdef _XB6_PRODUCT_REQ_
		case 0:
            _ansc_strcpy(modeStr, "None");
            break;
		case 3:
            _ansc_strcpy(modeStr, "WPA2-Personal");
            break;
		case 5:
            _ansc_strcpy(modeStr, "WPA2-Enterprise");
            break;
		default:
            //TODO: do nothing
            return 0;	
#else
        case 0:
            _ansc_strcpy(modeStr, "None");
            break;
        case 1:
            _ansc_strcpy(modeStr, "WEP-128");
            break;
        case 2:
            _ansc_strcpy(modeStr, "WPA-Personal");
            break;
        case 3:
            _ansc_strcpy(modeStr, "WPA2-Personal");
            break;
	case 5:
            _ansc_strcpy(modeStr, "WPA2-Enterprise");
            break;
        case 7:
            _ansc_strcpy(modeStr, "WPA-WPA2-Personal");
            break;
	case 8:
            _ansc_strcpy(modeStr, "WPA-WPA2-Enterprise");
            break;
        default:
            //TODO: do nothing
            return 0;
#endif
    }
    
    sprintf(valStr[0].parameterName, WIFI_DM_BSS_SECURITY_MODE, pEntry->IndexValue[0].Value.uValue);
    sprintf(valStr[0].parameterValue, "%s", modeStr);
    valStr[0].type = ccsp_string;

    retval = FindWifiDestComp();
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    if(mode == 3)
    {
		sprintf(valStr[1].parameterValue, "%s", "AES");
		sprintf(valStr[1].parameterName, WIFI_DM_BSS_ENCRYPTION, pEntry->IndexValue[0].Value.uValue);
        valStr[1].type = ccsp_string;
		valCnt = 2;
    }
    else if(mode == 7)
    {	
		sprintf(valStr[1].parameterValue, "%s", "AES+TKIP");
		sprintf(valStr[1].parameterName, WIFI_DM_BSS_ENCRYPTION, pEntry->IndexValue[0].Value.uValue);
        valStr[1].type = ccsp_string;
		valCnt = 2;
    }
    
    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, valCnt))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
        return -1;
    }

    return 0;
}

#define WIFI_DM_BSS_MAX_NUM_STA "Device.WiFi.AccessPoint.%d.X_CISCO_COM_BssMaxNumSta"

static int getBssMaxNumSta(PCCSP_TABLE_ENTRY pEntry)
{
    char dmStr[128] = {'\0'};
    char dmValue[64] = {'\0'};

    snprintf(dmStr, sizeof(dmStr), WIFI_DM_BSS_MAX_NUM_STA, pEntry->IndexValue[0].Value.uValue);

    if(get_dm_value(dmStr, dmValue, sizeof(dmValue)))
        return -1;

    return atoi(dmValue);
}

static int setBssMaxNumSta(PCCSP_TABLE_ENTRY pEntry, int num)
{
    parameterValStruct_t valStr;
	int retval;
    char str[2][80];
    valStr.parameterName = str[0];
    valStr.parameterValue = str[1];
    int valCnt =1;

    retval = FindWifiDestComp();
    CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    sprintf(valStr.parameterName, WIFI_DM_BSS_MAX_NUM_STA, pEntry->IndexValue[0].Value.uValue);
    sprintf(valStr.parameterValue, "%u", num);
    valStr.type = ccsp_int;
    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, valCnt))
    {
        CcspTraceError(("%s: fail to set: %s \n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

#define WIFI_DM_BSS_USER_STATUS "Device.WiFi.AccessPoint.%d.X_CISCO_COM_BssUserStatus"

static int getBssUserStatus(PCCSP_TABLE_ENTRY pEntry)
{
    char dmStr[128] = {'\0'};
    char dmValue[64] = {'\0'};

    snprintf(dmStr, sizeof(dmStr), WIFI_DM_BSS_USER_STATUS, pEntry->IndexValue[0].Value.uValue);

    if(get_dm_value(dmStr, dmValue, sizeof(dmValue)))
        return -1;

    return atoi(dmValue);
}

int Dot11BssTableCacheHelper(netsnmp_tdata *table)
{
    int status = 0;
    int i;
    netsnmp_tdata_row *row = NULL;
    PCCSP_TABLE_ENTRY pEntry = NULL;
    int mibIndex, dmIns;
    unsigned int *insArray = NULL;
    unsigned int *insCount = 0;
    const char *ssidDm = "Device.WiFi.SSID.";
    struct timespec ts;
    int nr_retry = 0;

    if(!table){
        status = -1;
        goto ret;
    }

    ts.tv_sec = 1;
    ts.tv_nsec = 0;
find_retry:    
    if (FindWifiDestComp() == FALSE){
        nr_retry++;
        if (nr_retry <= 60){
            nanosleep(&ts, NULL);
            goto find_retry;
        }else{
            status = -1;
            goto ret;
        }
    }


    if (!Cosa_GetInstanceNums(dstComp, dstPath, ssidDm, &insArray, &insCount)){
        status = -1;
        goto ret;
    }

    for(i = 0; i < insCount; i++){

        row = netsnmp_tdata_create_row();
        if(!row){
            AnscFreeMemory(pEntry);
            status = -1;
            goto ret;
        }

        dmIns = insArray[i];
       
        // We can do this, 'cause mapping is static
        pEntry = &gDot11Info[dmIns].entry;

        // save back-end instance number
        pEntry->IndexValue[0].Value.uValue = dmIns;
        pEntry->IndexCount = 1;

        row->data = pEntry;

        mibIndex = gDot11Info[dmIns].mib_index;
        netsnmp_tdata_row_add_index(row, ASN_UNSIGNED, &mibIndex, 4);

        if(table)
            netsnmp_tdata_add_row(table, row);
    }

ret:
    if (insArray)
        free(insArray);

    return status;
}
/* saRgDot11BssTable custom cache handler end */

int
Dot11BssTableHelper(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
)
{


netsnmp_request_info* req;
int subid = 0;
int intval = -1; /*RDKB-6911, CID-32993, init before use*/
int retval=SNMP_ERR_NOERROR;
PCCSP_TABLE_ENTRY entry = NULL;
netsnmp_variable_list *vb = NULL;
unsigned char mac[6] = {'\0'};
char ssid[33] = {'\0'}, defaultssid[33] = {'\0'};
char mode[33]= {'\0'};

for (req = requests; req != NULL; req = req->next)
{
	

    vb = req->requestvb;
    subid = vb->name[vb->name_length -2];
    CcspTraceInfo(("BssTable last 4: %d.%d.%d.%d\n", vb->name[vb->name_length-4],vb->name[vb->name_length-3],vb->name[vb->name_length-2],vb->name[vb->name_length-1]));
    entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
    if (entry == NULL) {
        netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
        CcspTraceWarning(("No entry found for BssTable\n"));
        continue;
    }
        
    switch (reqinfo->mode) {
        case MODE_GET:
        
            intval = -1;
            if(subid == saRgDot11BssEnable_subid) {
                intval = getBssEnable(entry);
            } else if (subid == saRgDot11BssAccessMode_subid) {
                intval = getBssAccessMode(entry);
            } else if (subid == saRgDot11BssClosedNetwork_subid) {
                intval = getBssClosedNetwork(entry);
            } else if (subid == saRgDot11BssHotSpot_subid) {
                intval = getBssHotSpot(entry);
            } else if (subid == saRgDot11BssIsolationEnable_subid) {
                intval = getBssIsolationEnable(entry);
            } else if (subid == saRgDot11BssId_subid){
                getBssid(entry, mac);
                snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)mac, 6);
                req->processed = 1;
                break;
            } else if (subid == saRgDot11BssSsid_subid){
                getSsid(entry, ssid);
                snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)ssid, strlen(ssid));
                req->processed = 1;
                break;
            } else if (subid == saRgDot11BssSecurityMode_subid){
                intval = getBssSecurityMode(entry);
            } else if (subid == saRgDot11BssMaxNumSta_subid){
                intval = getBssMaxNumSta(entry);
            } else if (subid == saRgDot11BssUserStatus_subid){
                intval = getBssUserStatus(entry);
            }else if( subid == saRgDot11BSSDefaultSSID_subid )
            {
				getDefaultSsid(entry,defaultssid);
                snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)defaultssid, strlen(defaultssid));
                req->processed = 1;

                
            }
            
            if (intval >= 0) {
                snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&intval, sizeof(intval));
                req->processed = 1;
                CcspTraceInfo(("BssTable, retrieved value %d\n", intval));
            } else
                CcspTraceWarning(("BssTable failed get call subid %d\n", subid));
        
        break;

        case MODE_SET_RESERVE1:
        /* sanity check */
            if (subid == saRgDot11BssEnable_subid) {
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, retval);
                } else if ( *(vb->val.integer) > 2 || *(vb->val.integer) < 1) {
                    // Not supporting enableOnline(3) for GA 1.2
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;
                }
                
                req->processed = 1;
            } else if (subid == saRgDot11BssAccessMode_subid) {
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, intval);
                    
                } else if ( *(vb->val.integer) > 2 || *(vb->val.integer) < 0) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;
                }
                req->processed = 1;
            } else if (subid == saRgDot11BssClosedNetwork_subid) {
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, intval);
                    
                } else if ( *(vb->val.integer) > 2 || *(vb->val.integer) < 1) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;
                }
                req->processed = 1;
            } else if (subid == saRgDot11BssHotSpot_subid) {
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, intval);
                } else if ( *(vb->val.integer) > 2 || *(vb->val.integer) < 1) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;
                }
                req->processed = 1;
            } else if (subid == saRgDot11BssIsolationEnable_subid) {
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, intval);
                    
                } else if ( *(vb->val.integer) > 1 || *(vb->val.integer) < 0) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;
                }
                req->processed = 1;
            } else if (subid == saRgDot11BssSsid_subid) {
                if ((retval=netsnmp_check_vb_type_and_max_size(req->requestvb, ASN_OCTET_STR, 32))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, retval);
                } 
                req->processed = 1;
            } else if (subid == saRgDot11BssSecurityMode_subid){
                if ((retval=netsnmp_check_vb_int_range(req->requestvb, 0, 8))!=SNMP_ERR_NOERROR)
                    netsnmp_set_request_error(reqinfo, req, retval);
                req->processed = 1;
            } else if (subid == saRgDot11BssMaxNumSta_subid){
                if ((retval=netsnmp_check_vb_int_range(req->requestvb, 1, 128))!=SNMP_ERR_NOERROR)
                    netsnmp_set_request_error(reqinfo, req, retval);
                req->processed = 1;
            }
                 /* request->processed will be reset in every step by netsnmp_call_handlers */
            break;

        case MODE_SET_RESERVE2:
        /* set value to backend with no commit */
            intval = 0;
            if(subid == saRgDot11BssEnable_subid) {
                intval = setBssEnable(entry, *(vb->val.integer));
                req->processed = 1;
            } else if (subid == saRgDot11BssAccessMode_subid) {
                intval = setBssAccessMode(entry, *(vb->val.integer));
                req->processed = 1;
            } else if (subid == saRgDot11BssClosedNetwork_subid) {
                intval = setBssClosedNetwork(entry, *(vb->val.integer));
                req->processed = 1;
            } else if (subid == saRgDot11BssHotSpot_subid) {
                intval = setBssHotSpot(entry, *(vb->val.integer));
                req->processed = 1;
            } else if (subid == saRgDot11BssIsolationEnable_subid) {
                intval = setBssIsolationEnable(entry, *(vb->val.integer));
                req->processed = 1;
            } else if (subid == saRgDot11BssSsid_subid){
                intval = setBssSsid(entry, vb->val.string);
                req->processed = 1;
            } else if (subid == saRgDot11BssSecurityMode_subid){
                intval = setBssSecurityMode(entry, *(vb->val.integer));
                req->processed = 1;
            } else if (subid == saRgDot11BssMaxNumSta_subid){
                intval = setBssMaxNumSta(entry, *(vb->val.integer));
                req->processed = 1;
            }
            
            if (intval) {
                netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                retval = SNMP_ERR_GENERR;
            } 
 
            break;

        case MODE_SET_ACTION:
        /* commit */

            /* 
             * Since cache is skipped, There is no way for plugin framework to know the CcspComp and CcspPath
             * Custom logic will handle the commit operation.
             */
            if(FindWifiDestComp() == TRUE)
                Cosa_SetCommit(dstComp, dstPath, TRUE);
            req->processed = 1;

            break;

        case MODE_SET_FREE:
            /*
             * FIXME call Cosa_SetCommit with commitFlag=FALSE
             */
            if(FindWifiDestComp() == TRUE)
                Cosa_SetCommit(dstComp, dstPath, FALSE);
            req->processed = 1; 
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
/*
<name>saRgDot11BssEnable</name>
<!-- <dm>
                    Note, CALLBACK REQUIRED. Int to boolean mapping mismatch, and 3 must be directed to own data model 
                    <paramName>Device.WiFi.SSID.%d.Enable</paramName>
                    <dataType>string</dataType>
                    <enumeration>enable(1),disable(2),enableOnline(3)</enumeration>
                </dm> -->

<mib>
                    <lastOid>6</lastOid>
                    <name>saRgDot11BssAccessMode</name>
                    <access>ReadWrite</access>
                    <dataType>INTEGER</dataType>
                    <range>
                        <min>0</min><max>2</max>
                    </range>
                </mib>
                <!-- <dm> -->
                    <!-- fill in DM param and type -->
                    <!-- Note, CALLBACK REQUIRED.  -->
                    <!-- <paramName>Device.WiFi.SSID.%d.X_CISCO_COM_MacFilter.Enable</paramName>
                    <paramName>Device.WiFi.SSID.{i}.X_CISCO_COM_MacFilter.FilterAsBlacklist</paramName>
                    <dataType>string</dataType>
                    <enumeration>allowAny(0),allowList(1),denyList(2)</enumeration> -->
                <!-- </dm> -->




*/

}


/*Not yet supported*/
int
handleRadiusTable(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
)
{
    netsnmp_request_info* req;
    int subid;
    int intval;
    int retval=SNMP_ERR_NOERROR;
    PCCSP_TABLE_ENTRY entry = NULL;
    netsnmp_variable_list *vb = NULL;

    for (req = requests; req != NULL; req = req->next)
    {
        vb = req->requestvb;
        subid = vb->name[vb->name_length -2];
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            continue;
        }
        switch (reqinfo->mode) {
            case MODE_GET:
                
                    
                    req->processed = 1;
                
                break;

            case MODE_SET_RESERVE1:
                /* sanity check */
                
                    
                    req->processed = 1;     /* request->processed will be reset in every step by netsnmp_call_handlers */
                    
                    
                
                break;

            case MODE_SET_RESERVE2:
                /* set value to backend with no commit */
                
                    
                    req->processed = 1;
                
         
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

/*<mib>
                    <lastOid>1</lastOid>
                    <name>saRgDot11RadiusAddressType</name>
                    <access>ReadWrite</access>
                    <dataType>InetAddressType</dataType>
                </mib>
                <!-- <dm>
                    Note, CALLBACK REQUIRED. unknown(0), ipv4(1), ipv6(2)
                    
                    <dataType>int</dataType>
                </dm> -->*/
return 0;
}


static int getCurrentChannel (PCCSP_TABLE_ENTRY entry) {
    parameterValStruct_t **valStr;
    int nval, retval;
    char str[2][80];
    char * name[2] = {(char*) str[0], (char*) str[1]};
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    snprintf(str[0], sizeof(str[0]),WIFI_DM_AUTOCHAN,entry->IndexValue[0].Value.uValue);
    snprintf(str[1], sizeof(str[1]),WIFI_DM_CHANNEL,entry->IndexValue[0].Value.uValue);

    if (!Cosa_GetParamValues(dstComp, dstPath, name, 2, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s or %s\n", __FUNCTION__, name[0], name[1]));
        return -1;
    }

    if (nval < 2)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    
    if(strncmp("true", valStr[0]->parameterValue, 5)==0) {
        /*If auto channel is enabled, val is 0*/
        retval = 0;
    } else {
        retval = atoi(valStr[1]->parameterValue);
    }
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int getWmm(PCCSP_TABLE_ENTRY entry) {
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[80];
    char* name = (char *)mystring;
    
    CcspTraceInfo(("getWmm called on entry: %d (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    snprintf(name, sizeof(mystring), WIFI_DM_WMM_ENABLE, entry->IndexValue[0].Value.uValue);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    retval = _ansc_strncmp("true", valStr[0]->parameterValue, 4) ? 0 : 1;
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int getWmmNoAck(PCCSP_TABLE_ENTRY entry){
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[80];
    char* name = (char *)mystring;
    
    CcspTraceInfo(("getWmmNoAck called on entry: %d (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    snprintf(name, sizeof(mystring), WIFI_DM_WMM_NOACK, entry->IndexValue[0].Value.uValue);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    sscanf(valStr[0]->parameterValue, "%d", &retval);
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int getMcastRate(PCCSP_TABLE_ENTRY entry){
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[80];
    char* name = (char *)mystring;
    
    CcspTraceInfo(("getMcastRate called on entry: %d (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    snprintf(name, sizeof(mystring), WIFI_DM_MCASTRATE, entry->IndexValue[0].Value.uValue);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    sscanf(valStr[0]->parameterValue, "%d", &retval);
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
    
}

static int getCountry(PCCSP_TABLE_ENTRY entry){
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[80];
    char* name = (char *)mystring;

    CcspTraceInfo(("%s called on entry: %d (%d)\n", __FUNCTION__, entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    snprintf(name, sizeof(mystring), WIFI_DM_RADIO_COUNTRY, entry->IndexValue[0].Value.uValue);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }

    retval = 0; // worldwide
    if (strstr(valStr[0]->parameterValue,"US") != NULL) {
        retval = 6; // USA code
    }

    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int getMbssUserControl(PCCSP_TABLE_ENTRY entry) 
{
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[80];
    char* name = (char *)mystring;

    CcspTraceInfo(("%s called on entry: %d (%d)\n", __FUNCTION__, entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    snprintf(name, sizeof(mystring), WIFI_DM_RADIO_USERCONTROL, entry->IndexValue[0].Value.uValue);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }

    retval = atoi(valStr[0]->parameterValue);
    retval = (retval << 16);

    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int getMbssAdminControl(PCCSP_TABLE_ENTRY entry) 
{
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[80];
    char* name = (char *)mystring;
    
    CcspTraceInfo(("%s called on entry: %d (%d)\n", __FUNCTION__, entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    snprintf(name, sizeof(mystring),  WIFI_DM_RADIO_ADMINCONTROL, entry->IndexValue[0].Value.uValue);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    retval = atoi(valStr[0]->parameterValue);
    retval = (retval << 16);
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int getOperMode(PCCSP_TABLE_ENTRY entry){
    parameterValStruct_t **valStr;
    int nval, retval;
    char str[80];
    char * name = (char*) str;
    
    /*Fetching*/
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    snprintf(str, sizeof(str),WIFI_DM_RADIO_ENABLE,entry->IndexValue[0].Value.uValue);
    

    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    /*Mapping*/
    if(strncmp("true", valStr[0]->parameterValue, 5)==0) {
        /*If radio enabled, val is local(3)*/
        retval = 3;
    } else {
        /*If radio disabled, return off(1)*/
        retval = 1;
    }
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setCurrentChannel(PCCSP_TABLE_ENTRY entry, int val){
    parameterValStruct_t valStr[2];
	int retval;
    char str[4][80];
    valStr[0].parameterName = str[0];
    valStr[0].parameterValue = str[1];
    valStr[1].parameterName = str[2];
    valStr[1].parameterValue = str[3];
    int valCnt =1;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    sprintf(valStr[0].parameterName, WIFI_DM_AUTOCHAN, entry->IndexValue[0].Value.uValue);
    valStr[0].type = ccsp_boolean;
    if (val == 0) {
        /*Set Autochannel*/
        sprintf(valStr[0].parameterValue, "%s", "true");
    } else {
        /*Explicitly set the channel*/
        sprintf(valStr[0].parameterValue, "%s", "false");
        sprintf(valStr[1].parameterName, WIFI_DM_CHANNEL, entry->IndexValue[0].Value.uValue);
        valStr[1].type = ccsp_unsignedInt;
        valCnt = 2;
        sprintf(valStr[1].parameterValue, "%u", val);
    }

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, valCnt))
    {
        CcspTraceError(("%s: fail to set: %s or %s\n", __FUNCTION__, valStr[0].parameterName, valStr[1].parameterName));
        return -1;
    }

    return 0;
}

static int setWmm(PCCSP_TABLE_ENTRY entry, int val){
    parameterValStruct_t valStr[MAX_APS_PER_RADIO];
	int retval;
    char str[MAX_APS_PER_RADIO][50];
    char valueString[10];
    int aps = MAX_APS_PER_RADIO;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    sprintf(valueString, "%s", val ? "true" : "false");
    
    // When enabling first enable Wmm then UAPSD
    if (val == 1) {
	
	SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, str, 50, &aps, WIFI_DM_WMM_ENABLE, valueString, ccsp_boolean);

	if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 1))
	{
	    CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
	    return -1;
	}

	SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, str, 50, &aps, WIFI_DM_WMM_UAPSD_ENABLE, valueString, ccsp_boolean);

	if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 1))
	{
	    CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
	    return -1;
	}
    } else {
    // When disabling first disable UAPSD then Wmm
	SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, str, 50, &aps, WIFI_DM_WMM_UAPSD_ENABLE, valueString, ccsp_boolean);
	
	if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 1))
	{
	    CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
	    return -1;
	}

	SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, str, 50, &aps, WIFI_DM_WMM_ENABLE, valueString, ccsp_boolean);

	if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 1))
	{
	    CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
	    return -1;
	}

    }

    return 0;
}

static int setWmmNoAck(PCCSP_TABLE_ENTRY entry, int val){
    parameterValStruct_t valStr[MAX_APS_PER_RADIO];
	int retval;
    char str[MAX_APS_PER_RADIO][60];
    char valueString[5];
    int aps = MAX_APS_PER_RADIO;
    
    sprintf(valueString, "%d", val);
    
    SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, str, 60, &aps, WIFI_DM_WMM_NOACK, valueString, ccsp_int);
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
        return -1;
    }

    return 0;
}

static int setMcastRate(PCCSP_TABLE_ENTRY entry, int val){
    parameterValStruct_t valStr[MAX_APS_PER_RADIO];
	int retval;
    char str[MAX_APS_PER_RADIO][60];
    char valueString[5];
    int aps = MAX_APS_PER_RADIO;
    
    sprintf(valueString, "%d", val);
    
    SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, str, 60, &aps, WIFI_DM_MCASTRATE, valueString, ccsp_int);
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
        return -1;
    }

    return 0;
}

static int setCountry(PCCSP_TABLE_ENTRY entry, int val){
    return 0;
}

static int setMbssUserControl(PCCSP_TABLE_ENTRY entry, int val)
{
    parameterValStruct_t valStr;
	int retval;
    char str[2][80];
    valStr.parameterName = str[0];
    valStr.parameterValue = str[1];
    int valCnt =1;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    sprintf(valStr.parameterName, WIFI_DM_RADIO_USERCONTROL, entry->IndexValue[0].Value.uValue);
    val = (val >> 16);
    sprintf(valStr.parameterValue, "%u", val );
    valStr.type = ccsp_int;
    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, valCnt))
    {
        CcspTraceError(("%s: fail to set: %s \n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

static int setMbssAdminControl(PCCSP_TABLE_ENTRY entry, int val)
{
    parameterValStruct_t valStr;
	int retval;
    char str[2][80];
    valStr.parameterName = str[0];
    valStr.parameterValue = str[1];
    int valCnt =1;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    sprintf(valStr.parameterName, WIFI_DM_RADIO_ADMINCONTROL, entry->IndexValue[0].Value.uValue);
    val = (val >> 16);
    sprintf(valStr.parameterValue, "%u", val );
    valStr.type = ccsp_int;
    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, valCnt))
    {
        CcspTraceError(("%s: fail to set: %s \n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

static int setOperMode(PCCSP_TABLE_ENTRY entry, int val){
    parameterValStruct_t valStr;
	int retval;
    char str[2][100];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    sprintf(valStr.parameterName, WIFI_DM_RADIO_ENABLE, entry->IndexValue[0].Value.uValue);
    sprintf(valStr.parameterValue, "%s", val == 1 || val == 0 ? "false" : "true");
    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

int
handleExtMgmtTable(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
)
{
    netsnmp_request_info* req;
    int subid;
    int intval;
    unsigned long ulongval;
    int retval=SNMP_ERR_NOERROR;
    PCCSP_TABLE_ENTRY entry = NULL;
    netsnmp_variable_list *vb = NULL;

    for (req = requests; req != NULL; req = req->next)
    {
        vb = req->requestvb;
        subid = vb->name[vb->name_length -2];
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            continue;
        }

        switch (reqinfo->mode) {
            case MODE_GET:
                intval = NOT_IMPLEMENTED;
                if (subid == saRgDot11ExtCurrentChannel_subid) {
                    intval = getCurrentChannel(entry);
                    if (intval >= 0) {
                        snmp_set_var_typed_value(req->requestvb, (u_char)ASN_UNSIGNED, (u_char *)&intval, sizeof(intval));
                        req->processed = 1;
                    }
                    else {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR); /*TODO: specific error handling*/
                        req->processed = 1;
                        //retval = SNMP_ERR_GENERR;
                    }
                    break;
                } else if (subid == saRgDot11ExtOperMode_subid) {
                    intval = getOperMode(entry);
                    
                } else if (subid == saRgDot11ExtCountry_subid) {
                    intval = getCountry(entry);
                    
                } else if (subid == saRgDot11ExtMbssUserControl_subid) {
                    intval = getMbssUserControl(entry);
                    
                } else if (subid == saRgDot11ExtMbssAdminControl_subid) {
                    intval = getMbssAdminControl(entry);
                    
                } else if (subid == saRgDot11ExtWmm_subid) {
                    intval = getWmm(entry);
                    
                } else if (subid == saRgDot11ExtWmmNoAck_subid) {
                    intval = getWmmNoAck(entry);
            
                } else if (subid == saRgDot11ExtMulticastRate_subid) {
                    intval = getMcastRate(entry);
                    
                }
                
                if (intval >= 0) {
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&intval, sizeof(intval));
                    req->processed = 1;
                }
                else {
                    if (intval == -1) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR); /*TODO: specific error handling*/
                        req->processed = 1;
                        //retval = SNMP_ERR_GENERR;
                    }
                }
                    
                    
                
                break;

            case MODE_SET_RESERVE1:
                /* sanity check */
                if (subid == saRgDot11ExtCurrentChannel_subid) {
                    if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_UNSIGNED))!=SNMP_ERR_NOERROR){
                        netsnmp_request_set_error(req, retval);
                    } else if ( *(vb->val.integer) > 216 || *(vb->val.integer) < 0) { /*Using integer value here. Shouldn't matter since value is well below int's capacity*/
                        netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                        retval = SNMP_ERR_BADVALUE;
                    }
                    req->processed = 1;
                } else if (subid == saRgDot11ExtOperMode_subid) {
                    if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                        netsnmp_request_set_error(req, retval);
                    }
                    req->processed = 1;
                } else if (subid == saRgDot11ExtCountry_subid) {
                    if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                        netsnmp_request_set_error(req, retval);
                    }
                    req->processed = 1;
                } else if (subid == saRgDot11ExtMbssUserControl_subid) {
                    if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                        netsnmp_request_set_error(req, retval);
                    }
                    req->processed = 1;
                } else if (subid == saRgDot11ExtMbssAdminControl_subid) {
                    if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                        netsnmp_request_set_error(req, retval);
                    }
                    req->processed = 1;
                } else if (subid == saRgDot11ExtWmm_subid) {
                    if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                        netsnmp_request_set_error(req, retval);
                    } else if ( *(vb->val.integer) > 1 || *(vb->val.integer) < 0 ) {
						netsnmp_set_request_error(reqinfo, req, SNMP_ERR_WRONGVALUE);
                        retval = SNMP_ERR_WRONGVALUE;
					}
                    req->processed = 1;
                } else if (subid == saRgDot11ExtWmmNoAck_subid) {
                    if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                        netsnmp_request_set_error(req, retval);
                    }
                    req->processed = 1;
                } else if (subid == saRgDot11ExtMulticastRate_subid) {
                    if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                        netsnmp_request_set_error(req, retval);
                    }
                    req->processed = 1;
                } 
                
                /*TODO: Individual bounds checking. DM handle this?*/
                
                    /* request->processed will be reset in every step by netsnmp_call_handlers */
                    
                
                break;

            case MODE_SET_RESERVE2:
                /* set value to backend with no commit */
                intval = -2;
                if (subid == saRgDot11ExtCurrentChannel_subid) {
                    intval = setCurrentChannel(entry, *(vb->val.integer));
                } else if (subid == saRgDot11ExtOperMode_subid) {
                    intval = setOperMode(entry, *(vb->val.integer));
                } else if (subid == saRgDot11ExtWmm_subid) {
                    intval = setWmm(entry, *(vb->val.integer));
                } else if (subid == saRgDot11ExtWmmNoAck_subid) {
                    intval = setWmmNoAck(entry, *(vb->val.integer));
                } else if (subid == saRgDot11ExtCountry_subid) {
                    intval = setCountry(entry, *(vb->val.integer));
                } else if (subid == saRgDot11ExtMbssUserControl_subid) {
                    intval = setMbssUserControl(entry, *(vb->val.integer));
                } else if (subid == saRgDot11ExtMbssAdminControl_subid) {
                    intval = setMbssAdminControl(entry, *(vb->val.integer));
                } else if (subid == saRgDot11ExtMulticastRate_subid) {
                    intval = setMcastRate(entry, *(vb->val.integer));
                }
                
                if (intval) {
                    if (intval == -1) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR); /*TODO: Specific error handling.*/
                        req->processed = 1;
                    }
                    //retval = SNMP_ERR_GENERR;
                } else {
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
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
                return SNMP_ERR_GENERR;
        }
    }

    return SNMP_ERR_NOERROR;
/*<mib>
                    <lastOid>1</lastOid>
                    <name>saRgDot11ExtOperMode</name>
                    <access>ReadWrite</access>
                    <dataType>INTEGER</dataType>
                    <range>
                        <min>0</min><max>3</max>
                    </range>
                </mib>
                <!-- <dm>
                     NOTE, CALLBACK REQUIRED. Non standard int to bool. Partial implementation. 
                    <paramName>Device.WiFi.Radio.%d.Enable</paramName>
                    <dataType>string</dataType>
                    <enumeration>off(1),local(3)</enumeration>
                </dm> -->

<mib>
                    <lastOid>3</lastOid>
                    <name>saRgDot11ExtCurrentChannel</name>
                    <access>ReadWrite</access>
                    <dataType>Unsigned32</dataType>
                    <range>
                        <min>0</min><max>216</max>
                    </range>
                </mib>
                <!-- <dm>
                     NOTE, CALLBACK REQUIRED. Set channel, or autochannel. 
                    <paramName>Device.WiFi.Radio.{i}.Channel</paramName>
                    <paramName>Device.WiFi.Radio.{i}.AutoChannelEnable</paramName>
                    <dataType>unsignedInt</dataType>
                </dm> -->


<mib>
                    <lastOid>14</lastOid>
                    <name>saRgDot11ExtCountry</name>
                    <access>ReadWrite</access>
                    <dataType>INTEGER</dataType>
                    <range>
                        <min>0</min><max>8</max>
                    </range>
                </mib>
                <!-- <dm>
                     NOTE, CALLBACK REQUIRED. ISO3166-2 2 char country code, then "" (all environments), "O" outside, or "I" inside.
                    <paramName> Device.WiFi.Radio.%d.RegulatoryDomain</paramName>
                    <dataType>string</dataType>
                    <enumeration>worldWide(0),thailand(1),israel(2),jordan(3),china(4),japan(5),usa(6),europe(7),allChannels(8)</enumeration>
                </dm> -->

<mib>
                    <lastOid>21</lastOid>
                    <name>saRgDot11ExtWmm</name>
                    <access>ReadWrite</access>
                    <dataType>INTEGER</dataType>
                    <range>
                        <min>0</min><max>1</max>
                    </range>
                </mib>
                <!-- <dm>
                     
                     NOTE, CALLBACK REQUIRED. to set all SSIDs on the given radio
                    <paramName>Device.WiFi.AccessPoint.%d.WMMEnable</paramName>
                    <dataType>string</dataType>
                    <enumeration>disable(0),enable(1)</enumeration>
                </dm> -->

<mapping>
                <mib>
                    <lastOid>22</lastOid>
                    <name>saRgDot11ExtWmmNoAck</name>
                    <access>ReadWrite</access>
                    <dataType>INTEGER</dataType>
                    <range>
                        <min>0</min><max>1</max>
                    </range>
                </mib>
                <!-- <dm>
                     
                    NOTE, CALLBACK REQUIRED. to set all SSIDs on the given radio
                    <paramName>Device.WiFi.AccessPoint.%d.X_CISCO_COM_WmmNoAck</paramName>
                    <dataType>string</dataType>
                    <enumeration>disable(0),enable(1)</enumeration>
                </dm> -->


<mib>
                    <lastOid>23</lastOid>
                    <name>saRgDot11ExtMulticastRate</name>
                    <access>ReadWrite</access>
                    <dataType>INTEGER</dataType>
                    <range>
                        <min>0</min><max>54</max>
                    </range>
                </mib>
                <!-- <dm>
                    
                    NOTE, CALLBACK REQUIRED. to set all SSIDs on the given radio
                    <paramName>Device.WiFi.AccessPoint.%d.X_CISCO_COM_MulticastRate</paramName>
                    <dataType>string</dataType>
                    <enumeration>disable(0),mbits1(1),mbits2(2),mbits5-5(5),mbits6(6),mbits9(9),mbits11(11),mbits12(12),mbits18(18),mbits24(24),mbits36(36),mbits48(48),mbits54(54)</enumeration>
                </dm> -->

*/


return 0;
}

int getNMode(PCCSP_TABLE_ENTRY entry) 
{
    parameterValStruct_t **valStr;
    int nval, retval = 1;
    char *a, *ac, *b,*g,*n;
    char mystring[50];
    char* name = (char *)mystring;
    
    //AnscTraceWarning(("getBssEnable called on entry: %d (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    snprintf(name, sizeof(mystring), WIFI_DM_OPERSTD, entry->IndexValue[0].Value.uValue);
  
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }
 
    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    n = _ansc_strchr(valStr[0]->parameterValue, 'n');
    b = _ansc_strchr(valStr[0]->parameterValue, 'b');
    g = _ansc_strchr(valStr[0]->parameterValue, 'g');
    a = _ansc_strchr(valStr[0]->parameterValue, 'a');
    ac = _ansc_strstr(valStr[0]->parameterValue, "ac");

    // if a and ac are not NULL and they are the same string, then move past the ac and search for an a by itself
    if (a && ac && (a  == ac)) {
        a = a+1;
        a = _ansc_strchr(a,'a');
    }
    
    retval = 0;
    if (a) {
        retval |= kAMask;
    }
    if (b) {
        retval |= kBMask;
    }
    if (g) {
        retval |= kGMask;
    }
    if (n) {
        retval |= kNMask;
    }
    if (ac) {
        retval |= kACMask;
    }

    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

int setNMode(PCCSP_TABLE_ENTRY entry, int val) 
{
    parameterValStruct_t valStr;
	int retval;
    char str[2][100];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    int fiveG;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    sprintf(valStr.parameterName, WIFI_DM_OPERSTD, entry->IndexValue[0].Value.uValue);

    // Init string
    valStr.parameterValue[0]  = '\0';

    fiveG = isRadio5GHz(entry->IndexValue[0].Value.uValue);

    if ((val == kNOff) ||  // not valid for either radio
        (fiveG && ((val & kBMask) || (val &kGMask))) || // b and g not valid for 5 GHz 
        (!fiveG && ((val & kAMask) || (val & kACMask)) ) )   // a and ac are not valid for 2.4 GHz 
    {
        CcspTraceError(("%s: Failed to set, unsupported value for %s %d for %s radio\n", __FUNCTION__, valStr.parameterName, val, (fiveG) ? "5 GHz" : "2.4 GHz"));
        return -1;
    } 

    if (val == kAuto) {
        if (fiveG) {
            val = kAMask | kNMask;
        } else {
            val = kGMask | kNMask;
        }
    } 
    if (val == kNOnly) {
        val = kNMask; 
    } 

    if (fiveG) { // 5 GHz
        if (val & kAMask) {
            strcat(valStr.parameterValue,"a,");
        }
        if (val & kACMask) {
            strcat(valStr.parameterValue,"ac,");
        }
    } else { // 2.4 GHz
        if (val & kBMask) {
            strcat(valStr.parameterValue,"b,");
        }
        if (val & kGMask) {
            strcat(valStr.parameterValue,"g,");
        }
    }

    // Can be on both 2.4 or 5
    if (val & kNMask) {
        strcat(valStr.parameterValue,"n,");
    }
    // remove last comma
    valStr.parameterValue[strlen(valStr.parameterValue)-1]  = '\0';
    valStr.type = ccsp_string;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

int getNPhyRate(PCCSP_TABLE_ENTRY entry) {
    parameterValStruct_t **valStr;
    int nval, retval;
    char mystring[50];
    char* name = (char *)mystring;
    return 0; //TODO: DATA MODEL NOT READY. IMPLEMENTATION DEFERRED.
    //AnscTraceWarning(("getBssEnable called on entry: %d (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    snprintf(name, sizeof(mystring), WIFI_DM_NPHYRATE, entry->IndexValue[0].Value.uValue);
    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }
    
    retval = _ansc_strncmp("true", valStr[0]->parameterValue, 5) ? 2 : 1;//TODO: MAPPING
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

int setNPhyRate(PCCSP_TABLE_ENTRY entry, int val) {
    parameterValStruct_t valStr;
	int retval;
    char str[2][100];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    return 0; //TODO: DATA MODEL NOT READY. IMPLEMENTATION DEFERRED.
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    sprintf(valStr.parameterName, WIFI_DM_NPHYRATE, entry->IndexValue[0].Value.uValue);
    sprintf(valStr.parameterValue, "%s", val == 1 ? "true" : "false"); //TODO: MAPPING
    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

int
handleNExtTable(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
)
{
    netsnmp_request_info* req;
    int subid;
    int intval;
    int retval=SNMP_ERR_NOERROR;
    PCCSP_TABLE_ENTRY entry = NULL;
    netsnmp_variable_list *vb = NULL;

    for (req = requests; req != NULL; req = req->next)
    {
        vb = req->requestvb;
        subid = vb->name[vb->name_length -2];
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            continue;
        }
        switch (reqinfo->mode) {
            case MODE_GET:
                intval = NOT_IMPLEMENTED;
                if (subid == saRgDot11nExtMode_subid) {
                    intval = getNMode(entry);
                } else if (subid == saRgDot11nExtPhyRate_subid) {
                    intval = getNPhyRate(entry);
                }
                
                if (intval >= 0) {
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&intval, sizeof(intval));
                    req->processed = 1;
                }
                else {
                    if (intval == -1) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR); /*TODO: specific error handling*/
                        req->processed = 1;
                        //retval = SNMP_ERR_GENERR;
                    }
                }
                    //req->processed = 1;
                
                break;

            case MODE_SET_RESERVE1:
                /* sanity check */
                if (subid == saRgDot11nExtMode_subid) {
                    if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                        netsnmp_request_set_error(req, retval);
                    }
                    req->processed = 1;
                } else if (subid == saRgDot11nExtPhyRate_subid) {
                    if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                        netsnmp_request_set_error(req, retval);
                    }
                    req->processed = 1;
                }
                //req->processed = 1;     /* request->processed will be reset in every step by netsnmp_call_handlers */
                    
                    
                
                break;

            case MODE_SET_RESERVE2:
                /* set value to backend with no commit */
                intval = NOT_IMPLEMENTED;
                if (subid == saRgDot11nExtMode_subid) {
                    intval = setNMode(entry, *(vb->val.integer));
                } else if (subid == saRgDot11nExtPhyRate_subid) {
                    intval = setNPhyRate(entry, *(vb->val.integer));
                }
                
                if (intval) {
                    if (intval == -1) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR); /*TODO: Specific error handling.*/
                        req->processed = 1;
                    }
                    //retval = SNMP_ERR_GENERR;
                } else {
                    req->processed = 1;
                }     
                    
                   // req->processed = 1;
                
         
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
/*
<mib>
                    <lastOid>1</lastOid>
                    <name>saRgdot11nExtMode</name>
                    <access>ReadWrite</access>
                    <dataType>INTEGER</dataType>
                    <range>
                        <min>1</min><max>3</max>
                    </range>
                </mib>
                <!--<dm>
                     Note, CALLBACK REQUIRED 
                    <paramName>Device.WiFi.Radio.%d.OperatingStandards</paramName>
                    <dataType>string</dataType>

                    <enumeration>auto(1),off(2),n-only(3)</enumeration>
                </dm>-->

<mib>
                    <lastOid>2</lastOid>
                    <name>saRgdot11nExtPhyRate</name>
                    <access>ReadWrite</access>
                    <dataType>INTEGER</dataType>
                </mib>
                <dm>
                    <!-- Note, CALLBACK REQUIRED. 0 to -1 translation for auto mode -->
                    <paramName>Device.WiFi.Radio.%d.MCS</paramName>
                    <dataType>int</dataType>
                </dm>


*/
}

static int getWpaDefaultPSK(PCCSP_TABLE_ENTRY pEntry, char *key)
{
    char dmStr[128] = {'\0'};

	

    if(!key)
        return -1;

	

    snprintf(dmStr, sizeof(dmStr), WIFI_DM_DEFAULT_PSK, pEntry->IndexValue[0].Value.uValue);
    if(get_dm_value(dmStr, key, 64))
        return -1;

	

    return 0; 
}

static int getWpaPSK(PCCSP_TABLE_ENTRY pEntry, char *key)
{
    char dmStr[128] = {'\0'};

    if(!key)
        return -1;

    snprintf(dmStr, sizeof(dmStr), WIFI_DM_PSK, pEntry->IndexValue[0].Value.uValue);
    if(get_dm_value(dmStr, key, 64))
        return -1;

    return 0; 
}

int setWpaPSK(PCCSP_TABLE_ENTRY entry, char *key, int keyLen) {
    parameterValStruct_t valStr;
	int retval;
    char str[2][100];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    char *mappedVal;
    int fiveG;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    sprintf(valStr.parameterName, WIFI_DM_PSK, entry->IndexValue[0].Value.uValue);
    sprintf(valStr.parameterValue, "%s", key); 
    valStr.type = ccsp_string;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

int
handleDot11WpaTable(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
)
{
    netsnmp_request_info* req;
    int subid;
    int intval;
    int retval=SNMP_ERR_NOERROR;
    PCCSP_TABLE_ENTRY entry = NULL;
    netsnmp_variable_list *vb = NULL;
    char value[64]={'\0'},defpskvalue[64]={'\0'};

    for (req = requests; req != NULL; req = req->next)
    {
        vb = req->requestvb;
        subid = vb->name[vb->name_length -2];
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            continue;
        }
        switch (reqinfo->mode) {
            case MODE_GET:
                if (subid == saRgDot11WpaPreSharedKey_subid) {
                	if((entry->IndexValue[0].Value.uValue == 3) || (entry->IndexValue[0].Value.uValue == 4))
                	{
                	netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
                	 return SNMP_ERR_GENERR;
                	}
                     // This parameter can't be read, but snmp was defined as read/write
                    //unsigned char value = '\0';
					getWpaPSK(entry,value);
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&value, strlen(value));
                    req->processed = 1;
                }
				else if( subid ==saRgDot11WpaDefaultPreSharedKey_subid ){
					
					getWpaDefaultPSK(entry,defpskvalue);
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&defpskvalue, strlen(defpskvalue));
                    req->processed = 1;
				}	
					
                
                break;

            case MODE_SET_RESERVE1:
                /* sanity check */
                if (subid == saRgDot11WpaPreSharedKey_subid) {
                	if((entry->IndexValue[0].Value.uValue == 3) || (entry->IndexValue[0].Value.uValue == 4))
                	{
                	 netsnmp_request_set_error(req, SNMP_ERR_NOTWRITABLE);
                	  return SNMP_ERR_GENERR;
                	} 
                	else
                	{
                    // PSK is 64 and must be hex string
                    if ( (req->requestvb->val_len == 64) &&
                         ((retval=netsnmp_check_vb_type(req->requestvb, ASN_OCTET_STR))!=SNMP_ERR_NOERROR) ) {
                        netsnmp_request_set_error(req, retval);
                    }
                    req->processed = 1;
                	}
                }
                
                break;

            case MODE_SET_RESERVE2:
                /* set value to backend with no commit */
                intval = NOT_IMPLEMENTED;
                if (subid == saRgDot11WpaPreSharedKey_subid) {
                	if((entry->IndexValue[0].Value.uValue == 3) || (entry->IndexValue[0].Value.uValue == 4))
                	{
                	    netsnmp_request_set_error(req, SNMP_ERR_NOTWRITABLE);
                	    return SNMP_ERR_GENERR;
                	    
                	}
                        if(req->requestvb->val_len < 8 )
                        {
                            CcspTraceError(("%s: Length of Passphrase is less than 8\n", __FUNCTION__));
                            netsnmp_request_set_error(req, SNMP_ERR_INCONSISTENTVALUE);
                            return SNMP_ERR_GENERR;
                        }
                	else
                	{
                	  intval = setWpaPSK(entry, (char *)req->requestvb->val.string, req->requestvb->val_len);
                	}
                    
                }
                
                if (intval) {
                    if (intval == -1) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                        req->processed = 1;
                    }
                } else {
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
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
                return SNMP_ERR_GENERR;
        }
    }

    return SNMP_ERR_NOERROR;
/*
                <mib>
                    <lastOid>2</lastOid>
                    <name>saRgDot11WpaPreSharedKey</name>
                    <access>ReadWrite</access>
                    <dataType>OCTET STRING</dataType>
                    <range>
                        <min>8</min><max>64</max>
                    </range>
                </mib>


*/
}

#define EnableDcs_lastoid 1
#define WIFI_DM_DCSENABLE24      "Device.WiFi.Radio.1.X_RDKCENTRAL-COM_DCSEnable"
#define WIFI_DM_DCSENABLE5     "Device.WiFi.Radio.2.X_RDKCENTRAL-COM_DCSEnable"

int getEnableDcs()
{
	parameterValStruct_t **valStr;
    int nval, enabledcs;
int retval;
	char str[2][80] ={{0}};
	char * name[2] = {(char*) str[0], (char*) str[1]}; 
  
    retval = FindWifiDestComp(); 
	
    CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    } 
   snprintf(str[0], sizeof(str[0]),WIFI_DM_DCSENABLE24);
   snprintf(str[1], sizeof(str[1]),WIFI_DM_DCSENABLE5);

    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 2, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }

CcspTraceWarning(("%s: valStr[0]->parameterValue %s\n", __FUNCTION__,valStr[0]->parameterValue));
CcspTraceWarning(("%s: valStr[1]->parameterValue %s\n", __FUNCTION__,valStr[1]->parameterValue));
   if (!strncmp(valStr[0]->parameterValue, "false", 5 )  && !strncmp(valStr[1]->parameterValue, "false", 5))
    {
        enabledcs = 0;
    }
	else if (!strncmp(valStr[0]->parameterValue, "true", 4 )  && !strncmp(valStr[1]->parameterValue, "true", 4))
    {
        enabledcs = 3;
    }
    else if (!strncmp(valStr[0]->parameterValue, "true", 4 )  && !strncmp(valStr[1]->parameterValue, "false", 5))
    {
        enabledcs = 1;
    }
	else if (!strncmp(valStr[0]->parameterValue, "false", 5)  && !strncmp(valStr[1]->parameterValue, "true", 4))
    {
        enabledcs = 2;
    } 
    Cosa_FreeParamValues(nval, valStr);
     return enabledcs;

}

static int setEnableDcs(int val) {
	int retval;
	
    parameterValStruct_t valStr[2] ={{0}};
    
    char str[4][100] = {{0}};
    valStr[0].parameterName=str[0];
    valStr[0].parameterValue=str[1];
    valStr[1].parameterName=str[2];
    valStr[1].parameterValue=str[3];
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    } 
    snprintf(valStr[0].parameterName,sizeof(str[0]),WIFI_DM_DCSENABLE24);
	snprintf(valStr[1].parameterName,sizeof(str[2]),WIFI_DM_DCSENABLE5);
	if(val == 3)
   	{
		valStr[0].parameterValue = AnscCloneString("true");
		valStr[1].parameterValue = AnscCloneString("true");
    }
	else if(val == 2)
	{
		valStr[0].parameterValue = AnscCloneString("false");
		valStr[1].parameterValue = AnscCloneString("true");
	}
	else if(val == 1)
	{
		valStr[0].parameterValue = AnscCloneString("true");
		valStr[1].parameterValue = AnscCloneString("false");
	}
    else if(val == 0)
	{
		valStr[0].parameterValue = AnscCloneString("false");
		valStr[1].parameterValue = AnscCloneString("false");
	}

	valStr[0].type = ccsp_boolean;
	valStr[1].type = ccsp_boolean;
    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 2))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, WIFI_DM_DCSENABLE24));
        return -1;
    }

    return 0;
}

//#if 0
int
handleDcs(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
)
{
    netsnmp_request_info* req;
    int subid;
    int intval;
    int retval=SNMP_ERR_NOERROR;
    PCCSP_TABLE_ENTRY entry = NULL;
//    netsnmp_variable_list *vb = NULL;
    int value=0;
    netsnmp_variable_list *requestvb    = NULL;



    for (req = requests; req != NULL; req = req->next) {
         requestvb = req->requestvb;
		 subid = requestvb->name[requestvb->name_length - 2];
                 CcspTraceInfo((" subid is '%d'\n",subid));

        switch (reqinfo->mode) {
            case MODE_GET:
                if (subid == EnableDcs_lastoid) {                  
		   value = getEnableDcs();
			snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&value, sizeof(value));
		req->processed = 1;
                }	
                
                break;

	case MODE_SET_RESERVE1:
        /* sanity check */
        	 if (subid == EnableDcs_lastoid) {
	 		if ((retval=netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
		            netsnmp_request_set_error(requests, retval);
		        } 			
if ( *(requestvb->val.integer) < 0 || *(requestvb->val.integer) > 3 ) {
					netsnmp_set_request_error(reqinfo,requests, SNMP_ERR_WRONGVALUE);
		            retval = SNMP_ERR_WRONGVALUE;
				}
			}
            req->processed = 1;
            break;

    case MODE_SET_RESERVE2:
			intval = NOT_IMPLEMENTED;
        	if (subid == EnableDcs_lastoid) {
            	intval = setEnableDcs(*(req->requestvb->val.integer)); 
				if(intval == -1)
				{
					 netsnmp_request_set_error(req,SNMP_ERR_GENERR);
				}      		
       		}
			req->processed = 1;
        break;

            case MODE_SET_ACTION:
                /* commit */
                if(FindWifiDestComp() == TRUE)
            Cosa_SetCommit(dstComp, dstPath, TRUE);
                break;

            case MODE_SET_FREE:
                break;

            case MODE_SET_COMMIT:
        	break;

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

//#endif


