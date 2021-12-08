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
#include "safec_lib_common.h"
#include "syscfg.h"

#define WIFI_DM_OBJ          "Device.WiFi."
#define WIFI_DM_BSSENABLE    "Device.WiFi.SSID.%lu.Enable"
#define WIFI_DM_APPLY        "Device.WiFi.Radio.%d.X_CISCO_COM_ApplySetting"
#define WIFI_DM_MACF_ENABLE  "Device.WiFi.AccessPoint.%lu.X_CISCO_COM_MACFilter.Enable"
#define WIFI_DM_MACF_ASBL    "Device.WiFi.AccessPoint.%lu.X_CISCO_COM_MACFilter.FilterAsBlackList"
#define WIFI_DM_CHANNEL      "Device.WiFi.Radio.%lu.Channel"
#define WIFI_DM_AUTOCHAN     "Device.WiFi.Radio.%lu.AutoChannelEnable"
#define WIFI_DM_ADVERTISE    "Device.WiFi.AccessPoint.%lu.SSIDAdvertisementEnabled"
#define WIFI_DM_RADIO_ENABLE "Device.WiFi.Radio.%d.Enable"
#define WIFI_DM_RADIO_COUNTRY "Device.WiFi.Radio.%lu.RegulatoryDomain"
#define WIFI_DM_WMM_ENABLE   "Device.WiFi.AccessPoint.%lu.WMMEnable"
#define WIFI_DM_WMM_UAPSD_ENABLE   "Device.WiFi.AccessPoint.%d.UAPSDEnable"
#define WIFI_DM_WMM_NOACK    "Device.WiFi.AccessPoint.%lu.X_CISCO_COM_WmmNoAck"
#define WIFI_DM_MCASTRATE    "Device.WiFi.AccessPoint.%lu.X_CISCO_COM_MulticastRate"
#define WIFI_DM_OPERSTD      "Device.WiFi.Radio.%lu.OperatingStandards"
#define WIFI_DM_NPHYRATE     "Device.WiFi.Radio.%lu.MCS"
#define WIFI_DM_PSK          "Device.WiFi.AccessPoint.%lu.Security.X_COMCAST-COM_KeyPassphrase"
#define WIFI_DM_NUMBER_APS   "Device.WiFi.AccessPointNumberOfEntries"
#define WIFI_DM_BSSHOTSPOT  "Device.WiFi.AccessPoint.%lu.X_CISCO_COM_BssHotSpot"
#define WIFI_DM_BSSISOLATIONENABLE "Device.WiFi.AccessPoint.%lu.IsolationEnable"
#define WIFI_DM_RADIO_USERCONTROL "Device.WiFi.Radio.%lu.X_CISCO_COM_MbssUserControl"
#define WIFI_DM_RADIO_ADMINCONTROL "Device.WiFi.Radio.%lu.X_CISCO_COM_AdminControl"
#define WIFI_DM_BSSID         "Device.WiFi.SSID.%lu.BSSID"
#define WIFI_DM_SSID          "Device.WiFi.SSID.%lu.SSID"
#define WIFI_DM_WPS           "Device.WiFi.AccessPoint.%d.WPS.Enable"
#define WIFI_DM_WPSTIME       "Device.WiFi.AccessPoint.%d.WPS.X_CISCO_COM_WpsPushButton"
#define WIFI_DM_DEFAULT_SSID  "Device.WiFi.SSID.%lu.X_COMCAST-COM_DefaultSSID"
#define WIFI_DM_DEFAULT_PSK   "Device.WiFi.AccessPoint.%lu.Security.X_COMCAST-COM_DefaultKeyPassphrase"

#define MAX_APS_PER_RADIO 16

#define NOT_IMPLEMENTED -2 

#define MAX_VAL_SET 100

#define MAX_VAL_LEVEL 80

#define MAX_ARRAY_VALUE 6

#define NUM_DMVALUE_TYPES (sizeof(dmValue_type_table)/sizeof(dmValue_type_table[0]))

typedef struct dmValue_pair {
  char     *name;
  int      level;
} dmValue_PAIR;

dmValue_PAIR dmValue_type_table[] = {
  { "None",  0 },
  { "WEP-128",   1},
  { "WEP-64", 1},
  { "WPA2-Personal",  3},
  { "WPA2-Enterprise", 5  },
   { "WPA-WPA2-Personal", 7  },
    { "WPA-WPA2-Enterprise", 8  }
};

int dmValue_type_from_name(char *name, int *type_ptr)
{
  int rc = -1;
  int ind = -1;
  unsigned int i = 0;
  if((name == NULL) || (type_ptr == NULL))
     return 0;
  int length = strlen(name);

  for (i = 0 ; i < NUM_DMVALUE_TYPES ; ++i)
  {
      rc = strcmp_s(name,length, dmValue_type_table[i].name, &ind);
      ERR_CHK(rc);
      if((rc == EOK) && (!ind))
      {
          *type_ptr = dmValue_type_table[i].level;
          return 1;
      }
  }
  return 0;
}

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
    kACMask = 256,
    kAXMask = 512
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
    /*Coverity Fix CID :55100,61897 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[80]= {0};
    char* name = (char *)mystring;
    errno_t rc =-1; 
    AnscTraceError(("get number of APs \n" ));
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    // return 4;

    rc =  sprintf_s(name, sizeof(mystring), WIFI_DM_NUMBER_APS);
    if(rc < EOK)
    { 
         ERR_CHK(rc);
         return -1;
     }

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
    UNREFERENCED_PARAMETER(strSize);
    errno_t rc =-1;

    // Radio 1 has odd AP instance numbers 1,3,5,... and Radio 2 has even numbers.  Currently supporting 2 AP per radio
    int numAPs = getNumAPs();

    if (numAPs <= 0) {
        return -1;
    }

    *aps = numAPs/2;
 #if 0
    int i = 0;
    int offset = 0;
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
       rc =  sprintf_s(valStr[0].parameterName,strSize, dmFormat, radioInst);
         if(rc < EOK)
         {
           ERR_CHK(rc);
           return -1;
         }
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
	int retval = 0;
	
    parameterValStruct_t valStr[2];
    
    char str[4][MAX_VAL_SET];
    valStr[0].parameterName=str[0];
    valStr[0].parameterValue=str[1];
    valStr[1].parameterName=str[2];
    valStr[1].parameterValue=str[3];
    
    retval = FindWifiDestComp();
    errno_t rc =-1;
 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    if (val != 1)
        val = 0;

    rc =  sprintf_s(valStr[0].parameterName,MAX_VAL_SET, WIFI_DM_APPLY, 1);
    if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }
    rc =  sprintf_s(valStr[0].parameterValue,MAX_VAL_SET, "%s", val ? "true" : "false");
    if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

    valStr[0].type = ccsp_boolean;

    rc = sprintf_s(valStr[1].parameterName,MAX_VAL_SET, WIFI_DM_APPLY, 2);
    if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

    rc = sprintf_s(valStr[1].parameterValue,MAX_VAL_SET, "%s", val ? "true" : "false");
    if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

    valStr[1].type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 2))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, WIFI_DM_APPLY));
        return -1;
    }

    return 0;
}

static void* wifiCommitThread(void* arg) {
    UNREFERENCED_PARAMETER(arg);
    while(1) {
        pthread_mutex_lock(&commitMutex);
        while(!bPendingCommit)
            pthread_cond_wait(&commitCond, &commitMutex);
        
        bPendingCommit = 0;
        pthread_mutex_unlock(&commitMutex);
        Cosa_SetCommit(dstComp, dstPath, TRUE);
    }
    return NULL;
}

static int getWps(PCCSP_TABLE_ENTRY entry)
{
    UNREFERENCED_PARAMETER(entry);
    /* Coverity Fix CID :61965 , 65350 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char str[80]= {0};
    char * name = (char*) str;
    errno_t rc =-1;
    /*Fetching*/
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(str, sizeof(str),WIFI_DM_WPSTIME,1);
    if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

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

        Cosa_FreeParamValues(nval, valStr);
        nval = 0;
        valStr = NULL;
        rc = sprintf_s(str, sizeof(str),WIFI_DM_WPSTIME,2);
        if(rc < EOK)
       {
          ERR_CHK(rc);
          return -1;
        }

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
    UNREFERENCED_PARAMETER(entry);
    int retval = 0;
	
	parameterValStruct_t valStr;
    char str[2][MAX_VAL_SET];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp();
    errno_t rc =-1;	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    // Turn off Wps if wpsTime is 0, else enable it
    rc = sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_WPS,1);
    if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

   rc =  sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s",  (wpsTime == 0) ? "false": "true");
   if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

   rc = sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_WPS,2);
   if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

    rc = sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s",  (wpsTime == 0) ? "false": "true");
    if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

   rc =     sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_WPSTIME,1);
   if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

   rc = sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%d", wpsTime); 
   if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

    valStr.type = ccsp_int;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    rc = sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_WPSTIME,2);
    if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

   rc =  sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%d", wpsTime); 
    if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

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
 UNREFERENCED_PARAMETER(handler);
 UNREFERENCED_PARAMETER(reginfo);
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
        /* TODO CID: 69343 Structurally dead code - due to break*/
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
 UNREFERENCED_PARAMETER(handler);
 UNREFERENCED_PARAMETER(reginfo);
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
        /*TODO CID: 65239 Structurally dead code - due to break*/
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
    /*Coverity Fix CID :58234,62374 74754 UnInit var */
    parameterValStruct_t **valStr = NULL, **valStr2 = NULL;
    int nval = 0, retval = 0, nval2 =0;
    char mystring[30]= {0};
    char* name = (char *)mystring;
    errno_t rc =-1;
    
    CcspTraceInfo(("getBssEnable called on entry: %lu (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp();
	
    CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc =  sprintf_s(name, sizeof(mystring), WIFI_DM_BSSENABLE, entry->IndexValue[0].Value.uValue);
     if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

    if (!Cosa_GetParamValues(dstComp, dstPath, &name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name));
        return -1;
    }

    if(entry->IndexValue[0].Value.uValue % 2) 
    {
      rc  =  sprintf_s(name, sizeof(mystring), WIFI_DM_RADIO_ENABLE, 1);
      if(rc < EOK)             
     {
         ERR_CHK(rc);
         return -1;
     }


    }
    else
    {
        rc = sprintf_s(name, sizeof(mystring), WIFI_DM_RADIO_ENABLE, 2);
        if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }  
   }
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
	int retval = 0;
    char str[2][MAX_VAL_SET];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp();
    errno_t rc =-1;	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    // Not supporting enableOnline(3) for GA 1.2
    if (value <  1 || value > 2)
        return -1;

    rc = sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_BSSENABLE, entry->IndexValue[0].Value.uValue);  
     if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }
    rc = sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s", value == 1 ? "true" : "false");
    if(rc < EOK)
    {
         ERR_CHK(rc);
         return -1;
     }

    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

static int getBssAccessMode(PCCSP_TABLE_ENTRY entry) {
    /*Coverity Fix CID :54849,60302 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char str[2][100];
    char* name[2] = {(char*) str[0], (char*) str[1]};
    errno_t rc =-1;
    
    CcspTraceInfo(("getBssAccessMode called on entry: %lu\n", entry->IndexValue[0].Value.uValue));
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(str[0], sizeof(str[0]),WIFI_DM_MACF_ENABLE,entry->IndexValue[0].Value.uValue); 
     if(rc < EOK)
     {
           ERR_CHK(rc);
           return -1;
      }

    rc = sprintf_s(str[1], sizeof(str[1]),WIFI_DM_MACF_ASBL,entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
           ERR_CHK(rc);
           return -1;
      }


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
	int retval = 0;
    char str[4][MAX_VAL_LEVEL];
    valStr[0].parameterName = str[0];
    valStr[0].parameterValue = str[1];
    valStr[1].parameterName = str[2];
    valStr[1].parameterValue = str[3];
    int valCnt =1;
    errno_t rc =-1;    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    /*snprintf(name[0], sizeof(name[0]),WIFI_DM_MACF_ENABLE,entry->IndexValue[0].Value.uValue);
    snprintf(name[1], sizeof(name[1]),WIFI_DM_MACF_ASBL,entry->IndexValue[0].Value.uValue);*/
    rc = sprintf_s(valStr[0].parameterName,MAX_VAL_LEVEL, WIFI_DM_MACF_ENABLE, entry->IndexValue[0].Value.uValue);
     if(rc < EOK)
     {
           ERR_CHK(rc);
           return -1;
      }

    valStr[0].type = ccsp_boolean;
    if (value == 0) {
        /*allowAny*/
        rc = sprintf_s(valStr[0].parameterValue,MAX_VAL_LEVEL, "%s", "false");
        if(rc < EOK)
     {
           ERR_CHK(rc);
           return -1;
      }

    } else {
        /*Mac filter enabled*/
        rc = sprintf_s(valStr[0].parameterValue,MAX_VAL_LEVEL, "%s", "true");
         if(rc < EOK)
     {
           ERR_CHK(rc);
           return -1;
      }

        rc = sprintf_s(valStr[1].parameterName,MAX_VAL_LEVEL, WIFI_DM_MACF_ASBL, entry->IndexValue[0].Value.uValue);
        if(rc < EOK)
     {
           ERR_CHK(rc);
           return -1;
      }

        valStr[1].type = ccsp_boolean;
        valCnt = 2;
        if (value == 1) {
            /*allowList*/
            rc = sprintf_s(valStr[1].parameterValue,MAX_VAL_LEVEL, "%s", "false");
             if(rc < EOK)
            {
               ERR_CHK(rc);
               return -1;
             }


        } else {
            /*denyList*/
            rc = sprintf_s(valStr[1].parameterValue,MAX_VAL_LEVEL, "%s", "true");
             if(rc < EOK)
            {
               ERR_CHK(rc);
               return -1;
             }

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
    /* Coverity Fix CID :59117,66173  UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[100] = {0};
    char* name = (char *)mystring;
    errno_t rc =-1;
    
    CcspTraceInfo(("getBssClosedNetwork called on entry: %lu (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(name, sizeof(mystring), WIFI_DM_ADVERTISE, entry->IndexValue[0].Value.uValue);
     if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

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
	int retval = 0;
    char str[2][MAX_VAL_SET];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp();
    errno_t rc =-1;
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    if (value != 1)
        value = 2;

    rc = sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_ADVERTISE, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

    rc = sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s", value == 2 ? "true" : "false");
    if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

static int getBssHotSpot(PCCSP_TABLE_ENTRY entry) {
    /*Coverity Fix CID :68466,70095 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[100]= {0};
    char* name = (char *)mystring;
    retval = FindWifiDestComp();
    errno_t rc =-1;
    int ind =-1;
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(name, sizeof(mystring), WIFI_DM_BSSHOTSPOT, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

    CcspTraceInfo(("%s: called on entry: %lu %s(%d)\n", __func__, entry->IndexValue[0].Value.uValue, mystring, sizeof(mystring)));
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
    
    rc = strcmp_s("false",strlen("false"),valStr[0]->parameterValue,&ind);
    ERR_CHK(rc);
    retval = (ind) ? 1 : 2 ;
    
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setBssHotSpot(PCCSP_TABLE_ENTRY entry, int value) {
    parameterValStruct_t valStr;
	int retval = 0;
    char str[2][MAX_VAL_SET];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp();
    errno_t rc =-1;	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    if (value != 1)
        value = 2;

   rc =  sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_BSSHOTSPOT, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

    rc = sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s", value == 1 ? "true" : "false");
    if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}
static int getBssIsolationEnable(PCCSP_TABLE_ENTRY entry) {
    /*Coverity Fix CID :64290, 65182 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[100] = {0};
    char* name = (char *)mystring;
    errno_t rc =-1; 
    retval = FindWifiDestComp();
    int ind =-1;	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(name, sizeof(mystring), WIFI_DM_BSSISOLATIONENABLE, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }


    CcspTraceInfo(("%s: called on entry: %lu %s(%d)\n", __func__, entry->IndexValue[0].Value.uValue, mystring, sizeof(mystring)));
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
    
    rc =  strcmp_s("false",strlen("false"), valStr[0]->parameterValue, &ind);
    ERR_CHK(rc);
    retval = (ind)  ? 1 : 0;
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setBssIsolationEnable(PCCSP_TABLE_ENTRY entry, int value) {
    parameterValStruct_t valStr;
	int retval = 0;
    char str[2][MAX_VAL_SET];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    errno_t rc =-1;
    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    if (value != 1)
        value = 0;

    rc =sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_BSSISOLATIONENABLE, entry->IndexValue[0].Value.uValue);
   if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

   rc =  sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s", value == 1 ? "true" : "false");
   if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

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
    WIFI_IF_MAX = 17,
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
    errno_t rc =-1;
	if(pStr == NULL)
		return -1;
   		
    rc = memset_s(array,MAX_ARRAY_VALUE,0,MAX_ARRAY_VALUE);
    ERR_CHK(rc);
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
    errno_t rc =-1;

    if(!macArray)
        return -1;

     rc = sprintf_s(dmStr, sizeof(dmStr), WIFI_DM_BSSID, pEntry->IndexValue[0].Value.uValue);
     if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

    if(get_dm_value(dmStr, mac, 18))
        return -1;

    return mac_string_to_array(mac, (unsigned char *)macArray);

}

static int getDefaultSsid(PCCSP_TABLE_ENTRY pEntry, char *defaultssid)
{
    char dmStr[128] = {'\0'};
    errno_t rc =-1;

    if(!defaultssid)
        return -1;

    rc = sprintf_s(dmStr, sizeof(dmStr), WIFI_DM_DEFAULT_SSID, pEntry->IndexValue[0].Value.uValue);
     if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

    if(get_dm_value(dmStr, defaultssid, 33))
       return -1;
    	

	

    return 0; 
}
static int getSsid(PCCSP_TABLE_ENTRY pEntry, char *ssid)
{
    char dmStr[128] = {'\0'};
    errno_t rc =-1;
    if(!ssid)
        return -1;

    rc = sprintf_s(dmStr, sizeof(dmStr), WIFI_DM_SSID, pEntry->IndexValue[0].Value.uValue);
     if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

    if(get_dm_value(dmStr, ssid, 33))
        return -1;

    return 0; 
}

static int setBssSsid(PCCSP_TABLE_ENTRY pEntry, const char *ssid)
{
    parameterValStruct_t valStr;
	int retval = 0;
    char str[2][MAX_VAL_SET];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    errno_t rc =-1;    
    retval = FindWifiDestComp();
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
  rc =   sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_SSID, pEntry->IndexValue[0].Value.uValue);
     if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

   rc =  sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s", ssid);
     if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }

    valStr.type = ccsp_string;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

#define WIFI_DM_BSS_SECURITY_MODE "Device.WiFi.AccessPoint.%lu.Security.ModeEnabled"
#define WIFI_DM_BSS_ENCRYPTION "Device.WiFi.AccessPoint.%lu.Security.X_CISCO_COM_EncryptionMethod"

static int getBssSecurityMode(PCCSP_TABLE_ENTRY pEntry)
{
    char dmStr[128] = {'\0'};
    char dmValue[64] = {'\0'};
    int level = 0; 
    if(!pEntry)
        return -1;
    errno_t rc =-1;
    rc = sprintf_s(dmStr, sizeof(dmStr), WIFI_DM_BSS_SECURITY_MODE, pEntry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
         ERR_CHK(rc);
         return -1;
     }


    if(get_dm_value(dmStr, dmValue, sizeof(dmValue)))
        return -1;

if (!dmValue_type_from_name(dmValue, &level))
         {
             return 0;
         }
#ifdef _XB6_PRODUCT_REQ
        if((level != 3) && (level != 5))
         return 0;
#endif
        return level;
}

static int setBssSecurityMode(PCCSP_TABLE_ENTRY pEntry, int mode)
{
    parameterValStruct_t valStr[2];
	int retval = 0;
    char str[4][MAX_VAL_SET];
    valStr[0].parameterName=str[0];
    valStr[0].parameterValue=str[1];
    valStr[1].parameterName = str[2];
    valStr[1].parameterValue = str[3];
    int valCnt =1;
    char modeStr[64] = {'\0'};
    errno_t rc = -1;

#ifdef _XB6_PRODUCT_REQ_
	switch(mode){
	       case 0:
               rc =  strcpy_s(modeStr,sizeof(modeStr), "None");
               if(rc != EOK)
                {
                       ERR_CHK(rc);
                       return -1;
                }
                break;
		case 3:
                rc = strcpy_s(modeStr,sizeof(modeStr), "WPA2-Personal");
                 if(rc != EOK)
                {
                       ERR_CHK(rc);
                       return -1;
                }

                break;
	        case 5:
                rc = strcpy_s(modeStr,sizeof(modeStr), "WPA2-Enterprise");
                if(rc != EOK)
                {
                       ERR_CHK(rc);
                       return -1;
                }
           
                break;
		default:
            //TODO: do nothing
            return 0;
        }
#else

   if (mode >= 0 && mode <= 8)
   {
        if (mode == 2 || mode == 4 || mode == 6)
            return 0; //do nothing

        unsigned int i = 0;
        for (i = 0 ; i < NUM_DMVALUE_TYPES ; ++i)
        {
            if ( dmValue_type_table[i].level == mode )
            {
                rc = strcpy_s(modeStr, sizeof(modeStr), dmValue_type_table[i].name);

                if (rc != EOK) {
                    ERR_CHK(rc);
                    return -1;
                }
                break;
            }
        }
   }
    else
       return 0;   //TODO: do nothing
      
#endif

    rc = sprintf_s(valStr[0].parameterName,MAX_VAL_SET, WIFI_DM_BSS_SECURITY_MODE, pEntry->IndexValue[0].Value.uValue);
    if(rc < EOK)
    {
       ERR_CHK(rc);
       return -1;
    }
    rc = sprintf_s(valStr[0].parameterValue,MAX_VAL_SET, "%s", modeStr);
    if(rc < EOK)
    {
       ERR_CHK(rc);
       return -1;
    }

    valStr[0].type = ccsp_string;

    retval = FindWifiDestComp();
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    if(mode == 3)
    {
		rc = sprintf_s(valStr[1].parameterValue,MAX_VAL_SET, "%s", "AES");
                if(rc < EOK)
                {
                  ERR_CHK(rc);
                  return -1;
                }

		rc =sprintf_s(valStr[1].parameterName,MAX_VAL_SET, WIFI_DM_BSS_ENCRYPTION, pEntry->IndexValue[0].Value.uValue);
                if(rc < EOK)
                {
                  ERR_CHK(rc);
                  return -1;
                }

        valStr[1].type = ccsp_string;
		valCnt = 2;
    }
/*CID: 92586 Logically dead code*/
#ifndef _XB6_PRODUCT_REQ_
    else if(mode == 7)
    {	
		rc = sprintf_s(valStr[1].parameterValue,MAX_VAL_SET, "%s", "AES+TKIP");
                if(rc < EOK)
                {
                  ERR_CHK(rc);
                  return -1;
                }

		rc = sprintf_s(valStr[1].parameterName, MAX_VAL_SET,WIFI_DM_BSS_ENCRYPTION, pEntry->IndexValue[0].Value.uValue);
                if(rc < EOK)
                {
                  ERR_CHK(rc);
                  return -1;
                }

               
        valStr[1].type = ccsp_string;
		valCnt = 2;
    }
#endif
    
    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, valCnt))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
        return -1;
    }

    return 0;
}

#define WIFI_DM_BSS_MAX_NUM_STA "Device.WiFi.AccessPoint.%lu.X_CISCO_COM_BssMaxNumSta"

static int getBssMaxNumSta(PCCSP_TABLE_ENTRY pEntry)
{
    char dmStr[128] = {'\0'};
    char dmValue[64] = {'\0'};
    errno_t rc =-1;

    rc = sprintf_s(dmStr, sizeof(dmStr), WIFI_DM_BSS_MAX_NUM_STA, pEntry->IndexValue[0].Value.uValue);
   if(rc < EOK)
   {
      ERR_CHK(rc);
      return -1;
    }


    if(get_dm_value(dmStr, dmValue, sizeof(dmValue)))
        return -1;

    return atoi(dmValue);
}

static int setBssMaxNumSta(PCCSP_TABLE_ENTRY pEntry, int num)
{
    parameterValStruct_t valStr;
	int retval = 0;
    char str[2][MAX_VAL_LEVEL];
    valStr.parameterName = str[0];
    valStr.parameterValue = str[1];
    int valCnt =1;
    errno_t rc =-1;
    retval = FindWifiDestComp();
    CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(valStr.parameterName,MAX_VAL_LEVEL, WIFI_DM_BSS_MAX_NUM_STA, pEntry->IndexValue[0].Value.uValue);
    if(rc < EOK)
   {
      ERR_CHK(rc);
      return -1;
    }

    rc = sprintf_s(valStr.parameterValue,MAX_VAL_LEVEL, "%u", num);
    if(rc < EOK)
   {
      ERR_CHK(rc);
      return -1;
    }

    
    valStr.type = ccsp_int;
    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, valCnt))
    {
        CcspTraceError(("%s: fail to set: %s \n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

#define WIFI_DM_BSS_USER_STATUS "Device.WiFi.AccessPoint.%lu.X_CISCO_COM_BssUserStatus"

static int getBssUserStatus(PCCSP_TABLE_ENTRY pEntry)
{
    char dmStr[128] = {'\0'};
     char dmValue[64] = {'\0'};
     errno_t rc =-1;

   rc =   sprintf_s(dmStr, sizeof(dmStr), WIFI_DM_BSS_USER_STATUS, pEntry->IndexValue[0].Value.uValue);
   if(rc < EOK)
   {
      ERR_CHK(rc);
      return -1;
    }


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
    unsigned int insCount = 0;
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


    if (!Cosa_GetInstanceNums(dstComp, dstPath, (char *)ssidDm, &insArray, &insCount)){
        status = -1;
        goto ret;
    }

    for(i = 0; i < (int)insCount; i++){
        
       row = netsnmp_tdata_create_row();
        if(!row){
            AnscFreeMemory(pEntry);
            status = -1;
            goto ret;
        }

        pEntry = (PCCSP_TABLE_ENTRY)AnscAllocateMemory(sizeof(CCSP_TABLE_ENTRY));

        if (!pEntry)
        {
            status = -1;
            goto ret;
        }
        /*CID: 151642 Wrong sizeof argument*/
        memset(pEntry,0,sizeof(CCSP_TABLE_ENTRY));

        dmIns = insArray[i];
                   if (WIFI_IF_MAX <= dmIns)
                   {
                               goto ret;
                   }

        // save back-end instance number
        pEntry->IndexValue[0].Value.uValue = dmIns;
        pEntry->IndexCount = 1;

        row->data = pEntry;

        mibIndex = gDot11Info[dmIns].mib_index;
        netsnmp_tdata_row_add_index(row, ASN_UNSIGNED, &mibIndex, 4);

         if( netsnmp_tdata_add_row(table, row) != SNMPERR_SUCCESS )
         goto ret;
         }
   return status;
        

    

ret:
    if (insArray)
        free(insArray);
     /* Coverity Fix CID : 135290 RESOURCE_LEAK */ 
      if(pEntry)
        AnscFreeMemory(pEntry); 

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
UNREFERENCED_PARAMETER(handler);
UNREFERENCED_PARAMETER(reginfo);

netsnmp_request_info* req;
int subid = 0;
int intval = -1; /*RDKB-6911, CID-32993, init before use*/
int retval=SNMP_ERR_NOERROR;
PCCSP_TABLE_ENTRY entry = NULL;
netsnmp_variable_list *vb = NULL;
unsigned char mac[MAX_ARRAY_VALUE] = {'\0'};
char ssid[33] = {'\0'}, defaultssid[33] = {'\0'};

for (req = requests; req != NULL; req = req->next)
{
	

    vb = req->requestvb;
    subid = vb->name[vb->name_length -2];
    CcspTraceInfo(("BssTable last 4: %lu.%lu.%lu.%lu\n", vb->name[vb->name_length-4],vb->name[vb->name_length-3],vb->name[vb->name_length-2],vb->name[vb->name_length-1]));
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
                getBssid(entry, (char *)mac);
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
                intval = setBssSsid(entry, (const char *)vb->val.string);
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
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info* req;
    PCCSP_TABLE_ENTRY entry = NULL;

    for (req = requests; req != NULL; req = req->next)
    {
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
    /* Coverity Fix CID :53601,61933 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char str[2][80];
    char * name[2] = {(char*) str[0], (char*) str[1]};
    errno_t rc =-1; 
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
   rc =  sprintf_s(str[0], sizeof(str[0]),WIFI_DM_AUTOCHAN,entry->IndexValue[0].Value.uValue);
   if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
    rc = sprintf_s(str[1], sizeof(str[1]),WIFI_DM_CHANNEL,entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

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
    /*Coverity Fix CID :70800,70873 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval= 0, retval = 0;
    char mystring[80]= {0};
    char* name = (char *)mystring;
    errno_t rc =-1;
    int ind =-1;
    
    CcspTraceInfo(("getWmm called on entry: %lu (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    rc = sprintf_s(name, sizeof(mystring), WIFI_DM_WMM_ENABLE, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
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
    
    rc = strcmp_s("true",strlen("true"),valStr[0]->parameterValue,&ind);
    ERR_CHK(rc); 
    retval = (ind) ? 0 : 1;
    
    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int getWmmNoAck(PCCSP_TABLE_ENTRY entry){
    /*Coverity Fix CID :64884,65135 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[80]= {0};
    char* name = (char *)mystring;
    errno_t rc =-1;
    
    CcspTraceInfo(("getWmmNoAck called on entry: %lu (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    rc = sprintf_s(name, sizeof(mystring), WIFI_DM_WMM_NOACK, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
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
    /*Coverity Fix CID :74901,  UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[80]= {0};
    char* name = (char *)mystring;
    errno_t rc =-1;
    
    CcspTraceInfo(("getMcastRate called on entry: %lu (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    rc = sprintf_s(name, sizeof(mystring), WIFI_DM_MCASTRATE, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
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
    /*Coverity Fix CID :54683,70704,71750  UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[80] =  {0};
    char* name = (char *)mystring;
    errno_t rc =-1;

    CcspTraceInfo(("%s called on entry: %lu (%d)\n", __FUNCTION__, entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    rc = sprintf_s(name, sizeof(mystring), WIFI_DM_RADIO_COUNTRY, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
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
    /*Coverity Fix CID :57199,71232 UnInit var */
    parameterValStruct_t **valStr= NULL;
    int nval = 0, retval = 0;
    char mystring[80]= {0};
    char* name = (char *)mystring;
    errno_t rc =-1;

    CcspTraceInfo(("%s called on entry: %lu (%d)\n", __FUNCTION__, entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    rc = sprintf_s(name, sizeof(mystring), WIFI_DM_RADIO_USERCONTROL, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
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
    /*Coverity Fix CID :57838,72697 UnInit var */
    parameterValStruct_t **valStr =  NULL;
    int nval = 0, retval = 0;
    char mystring[80] = {0};
    char* name = (char *)mystring;
    errno_t rc =-1;
    
    CcspTraceInfo(("%s called on entry: %lu (%d)\n", __FUNCTION__, entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
	
    /*Only perform get on one accesspoint, since all are set at same time. Assume 1 = 1 and 2 = 2 association in both AccessPoint and Radio tables*/
    rc = sprintf_s(name, sizeof(mystring),  WIFI_DM_RADIO_ADMINCONTROL, entry->IndexValue[0].Value.uValue);
     if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

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
    /*Coverity Fix CID :53670 ,72007 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char str[80] = {0};
    char * name = (char*) str;
    errno_t rc =-1; 
    /*Fetching*/
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(str, sizeof(str),WIFI_DM_RADIO_ENABLE,(int)entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

    
    

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
	int retval = 0;
    char str[4][MAX_VAL_LEVEL];
    valStr[0].parameterName = str[0];
    valStr[0].parameterValue = str[1];
    valStr[1].parameterName = str[2];
    valStr[1].parameterValue = str[3];
    int valCnt =1;
    errno_t rc =-1; 
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(valStr[0].parameterName,MAX_VAL_LEVEL, WIFI_DM_AUTOCHAN, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

    valStr[0].type = ccsp_boolean;
    if (val == 0) {
        /*Set Autochannel*/
       rc =      sprintf_s(valStr[0].parameterValue,MAX_VAL_LEVEL, "%s", "true");
        if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

	//Log will be printed inside SNMP.txt in rdklogs//RDKB-23380
	CcspTraceInfo(("RDKB_SNMP : Autochannel is Enabled through SNMP for Radio %lu\n",entry->IndexValue[0].Value.uValue));
    } else {
        /*Explicitly set the channel*/
        rc = sprintf_s(valStr[0].parameterValue,MAX_VAL_LEVEL, "%s", "false");
        if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

       rc =  sprintf_s(valStr[1].parameterName,MAX_VAL_LEVEL, WIFI_DM_CHANNEL, entry->IndexValue[0].Value.uValue);
       if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

        valStr[1].type = ccsp_unsignedInt;
        valCnt = 2;
       rc =  sprintf_s(valStr[1].parameterValue,MAX_VAL_LEVEL, "%u", val);
       if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

	//Log will be printed inside SNMP.txt in rdklogs//RDKB-23380
	CcspTraceInfo(("RDKB_SNMP : Autochannel is Disabled through SNMP\n"));
	CcspTraceInfo(("RDKB_SNMP : Channel is Modified for Radio %lu and channel selected is %u \n",entry->IndexValue[0].Value.uValue,val));
    }

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, valCnt))
    {
        CcspTraceError(("%s: fail to set: %s or %s\n", __FUNCTION__, valStr[0].parameterName, valStr[1].parameterName));
        return -1;
    }

    return 0;
}

static int setWmm(PCCSP_TABLE_ENTRY entry, int val){
   /* Coverity Fix CID :61641 UnInit var */ 
   parameterValStruct_t valStr[MAX_APS_PER_RADIO] = {{0}};
	int retval = 0;
    char str[MAX_APS_PER_RADIO][50] = {{0}};
    char valueString[10]= {0};
    int aps = MAX_APS_PER_RADIO;
    errno_t rc =-1;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    rc = sprintf_s(valueString,sizeof(valueString), "%s", val ? "true" : "false");
     if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

    
    // When enabling first enable Wmm then UAPSD
    if (val == 1) {
	
	SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, (char *)str, 50, &aps, WIFI_DM_WMM_ENABLE, valueString, ccsp_boolean);

	if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 1))
	{
	    CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
	    return -1;
	}

	SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, (char *)str, 50, &aps, WIFI_DM_WMM_UAPSD_ENABLE, valueString, ccsp_boolean);

	if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 1))
	{
	    CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
	    return -1;
	}
    } else {
    // When disabling first disable UAPSD then Wmm
	SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, (char *)str, 50, &aps, WIFI_DM_WMM_UAPSD_ENABLE, valueString, ccsp_boolean);
	
	if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 1))
	{
	    CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
	    return -1;
	}

	SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, (char *)str, 50, &aps, WIFI_DM_WMM_ENABLE, valueString, ccsp_boolean);

	if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, valStr, 1))
	{
	    CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr[0].parameterName));
	    return -1;
	}

    }

    return 0;
}

static int setWmmNoAck(PCCSP_TABLE_ENTRY entry, int val){
    /*Coverity Fix CID :72254  UnInit var */
    parameterValStruct_t valStr[MAX_APS_PER_RADIO] = {{0}};
	int retval = 0;
    char str[MAX_APS_PER_RADIO][60];
    char valueString[5];
    int aps = MAX_APS_PER_RADIO;
    errno_t rc =-1;   
     rc = sprintf_s(valueString,sizeof(valueString), "%d", val);
     if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
    
    SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, (char *)str, 60, &aps, WIFI_DM_WMM_NOACK, valueString, ccsp_int);
    
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
    /*Coverity Fix CID :61890 UnInit var */
    parameterValStruct_t valStr[MAX_APS_PER_RADIO] = {{0}};
	int retval = 0;
    char str[MAX_APS_PER_RADIO][60] = {{0}};
    char valueString[5] = {0};
    int aps = MAX_APS_PER_RADIO;
    errno_t rc =-1;
    
    rc = sprintf_s(valueString,sizeof(valueString), "%d", val);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

    
    SetAllAPsonRadio(entry->IndexValue[0].Value.uValue, valStr, (char *)str, 60, &aps, WIFI_DM_MCASTRATE, valueString, ccsp_int);
    
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
    UNREFERENCED_PARAMETER(entry);
    UNREFERENCED_PARAMETER(val);
    return 0;
}

static int setMbssUserControl(PCCSP_TABLE_ENTRY entry, int val)
{
    parameterValStruct_t valStr;
	int retval = 0;
    char str[2][MAX_VAL_LEVEL];
    valStr.parameterName = str[0];
    valStr.parameterValue = str[1];
    int valCnt =1;
    errno_t rc =-1;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(valStr.parameterName,MAX_VAL_LEVEL, WIFI_DM_RADIO_USERCONTROL, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
    
    val = (val >> 16);
    rc = sprintf_s(valStr.parameterValue,MAX_VAL_LEVEL, "%u", val );
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
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
	int retval = 0;
    char str[2][MAX_VAL_LEVEL];
    valStr.parameterName = str[0];
    valStr.parameterValue = str[1];
    int valCnt =1;
    errno_t rc =-1;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(valStr.parameterName,MAX_VAL_LEVEL, WIFI_DM_RADIO_ADMINCONTROL, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

    val = (val >> 16);
   rc =  sprintf_s(valStr.parameterValue,MAX_VAL_LEVEL ,"%u", val );
   if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

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
	int retval = 0;
    char str[2][MAX_VAL_SET];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    retval = FindWifiDestComp(); 
    errno_t rc =-1;
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    rc = sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_RADIO_ENABLE, (int)entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
   rc =  sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s", val == 1 || val == 0 ? "false" : "true");
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
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
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
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
    /*Coverity Fix CID :62899,63675 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 1;
    char *a, *ac, *b,*g,*n;
#if defined (_WIFI_AX_SUPPORT_)
    char *ax;
#endif
    char mystring[50]= {0};
    char* name = (char *)mystring;
     errno_t rc =-1; 
    //AnscTraceWarning(("getBssEnable called on entry: %d (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(name, sizeof(mystring), WIFI_DM_OPERSTD, entry->IndexValue[0].Value.uValue);  
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
  
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

#if defined (_WIFI_AX_SUPPORT_)
    ax = _ansc_strstr(valStr[0]->parameterValue, "ax");

    // if a and ac or ax are not NULL and a is the same string, then move past the ac or ax and search for an a by itself
    if ( (a && ac && (a  == ac)) || (a && ax && (a  == ax)))
    {
        a = a+1;
        a = _ansc_strchr(a,'a');

       // if a, ac, and ax are not NULL we must double check
       if( a && ac && ax) 
       {
       	if ( (a && ac && (a  == ac)) || (a && ax && (a  == ax)))
       	{
       		a = a+1;
       		a = _ansc_strchr(a,'a');	
       	}
       }
    }
#else
    // if a and ac are not NULL and they are the same string, then move past the ac and search for an a by itself
    if (a && ac && (a  == ac)) {
        a = a+1;
        a = _ansc_strchr(a,'a');
    }
#endif
    
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

#if defined (_WIFI_AX_SUPPORT_)
    if (ax) {
        retval |= kAXMask;
    }
#endif

    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

int setNMode(PCCSP_TABLE_ENTRY entry, int val) 
{
    parameterValStruct_t valStr;
	int retval = 0;
    char str[2][MAX_VAL_SET];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    int fiveG;
    errno_t rc =-1;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    rc = sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_OPERSTD, entry->IndexValue[0].Value.uValue);
     if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

    // Init string
    valStr.parameterValue[0]  = '\0';

    fiveG = isRadio5GHz(entry->IndexValue[0].Value.uValue);

#if !defined (_WIFI_AX_SUPPORT_)
    if (((val == kNOff) || (val & kAXMask)) ||  // not valid for either radio
        (fiveG && ((val & kBMask) || (val & kGMask) ) ) || // b and g not valid for 5 GHz 
        (!fiveG && ((val & kAMask) || (val & kACMask) ) ) )   // a and ac are not valid for 2.4 GHz
#else
    if ((val == kNOff) ||  // not valid for either radio
        (fiveG && ((val & kBMask) || (val & kGMask))) || // b and g not valid for 5 GHz 
        (!fiveG && ((val & kAMask) || (val & kACMask)) ) )   // a and ac are not valid for 2.4 GHz 
#endif
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
            rc = strcat_s(valStr.parameterValue,MAX_VAL_SET,"a,");
              if(rc != EOK)
             {
                  ERR_CHK(rc);
                  return -1;
             }

        }
        if (val & kACMask) {
               rc =    strcat_s(valStr.parameterValue,MAX_VAL_SET,"ac,");
               if(rc != EOK)
             {
                  ERR_CHK(rc);
                  return -1;
             }
        }
    } else { // 2.4 GHz
        if (val & kBMask) {
            rc = strcat_s(valStr.parameterValue,MAX_VAL_SET,"b,");
             if(rc != EOK)
             {
                  ERR_CHK(rc);
                  return -1;
             }
        }
        if (val & kGMask) {
            rc = strcat_s(valStr.parameterValue,MAX_VAL_SET,"g,");
            if(rc != EOK)
             {
                  ERR_CHK(rc);
                  return -1;
             }
        }
    }

    // Can be on both 2.4 or 5
    if (val & kNMask) {
         rc = strcat_s(valStr.parameterValue,MAX_VAL_SET,"n,");
          if(rc != EOK)
             {
                  ERR_CHK(rc);
                  return -1;
             }

    }
#if defined (_WIFI_AX_SUPPORT_)
    if (val & kAXMask) {
      rc =   strcat_s(valStr.parameterValue,MAX_VAL_SET,"ax,");
      if(rc != EOK)
             {
                  ERR_CHK(rc);
                  return -1;
             }

    }
#endif
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
    UNREFERENCED_PARAMETER(entry);
   // char mystring[50] = {0};
    CcspTraceInfo(("%s: not implemented\n", __func__));
    return 0; //TODO: DATA MODEL NOT READY. IMPLEMENTATION DEFERRED.

    //AnscTraceWarning(("getBssEnable called on entry: %d (%d)\n", entry->IndexValue[0].Value.uValue, sizeof(mystring)));
    /*CID: 67296 Structurally dead code*/
#if 0 
    errno_t rc =-1;
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }
    
    rc = sprintf_s(name, sizeof(mystring), WIFI_DM_NPHYRATE, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
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
#endif
}

int setNPhyRate(PCCSP_TABLE_ENTRY entry, int val) {
#if 0
    char str[2][MAX_VAL_SET];
    parameterValStruct_t valStr;
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
#endif
    UNREFERENCED_PARAMETER(entry);
    UNREFERENCED_PARAMETER(val);
    CcspTraceInfo(("%s: not implemented\n", __func__));
    return 0; //TODO: DATA MODEL NOT READY. IMPLEMENTATION DEFERRED.

    /* CID: 70719 Structurally dead code*/
#if 0
    int retval = 0;
    errno_t rc =-1;
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    rc = sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_NPHYRATE, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
   rc =  sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s", val == 1 ? "true" : "false"); //TODO: MAPPING
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }

    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
#endif
}

int
handleNExtTable(
    netsnmp_mib_handler				*handler,
    netsnmp_handler_registration	*reginfo,
    netsnmp_agent_request_info		*reqinfo,
    netsnmp_request_info		 	*requests
)
{
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
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
    errno_t rc =-1;	

    if(!key)
        return -1;

	

    rc =sprintf_s(dmStr, sizeof(dmStr), WIFI_DM_DEFAULT_PSK, pEntry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
    if(get_dm_value(dmStr, key, 64))
        return -1;

	

    return 0; 
}

static int getWpaPSK(PCCSP_TABLE_ENTRY pEntry, char *key)
{
    char dmStr[128] = {'\0'};
    errno_t rc =-1;

    if(!key)
        return -1;

   rc =  sprintf_s(dmStr, sizeof(dmStr), WIFI_DM_PSK, pEntry->IndexValue[0].Value.uValue);
   if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
    if(get_dm_value(dmStr, key, 64))
        return -1;

    return 0; 
}

int setWpaPSK(PCCSP_TABLE_ENTRY entry, char *key, int keyLen) {
    UNREFERENCED_PARAMETER(keyLen);
    parameterValStruct_t valStr;
	int retval = 0;
    char str[2][MAX_VAL_SET];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    errno_t rc =-1;
    
    retval = FindWifiDestComp(); 
	
	CcspTraceInfo(("%s: FindWifiDestComp returned %s\n", __func__, (retval == TRUE) ? "True" : "False"));
    if (retval != TRUE) {
       return -1;
    }

    rc =  sprintf_s(valStr.parameterName,MAX_VAL_SET, WIFI_DM_PSK, entry->IndexValue[0].Value.uValue);
    if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
     rc = sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s", key); 
     if(rc < EOK)
     {
            ERR_CHK(rc);
            return -1;
      }
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
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info* req;
    int subid;
    int intval;
    int retval=SNMP_ERR_NOERROR;
    PCCSP_TABLE_ENTRY entry = NULL;
    netsnmp_variable_list *vb = NULL;
    char value[64]={'\0'},defpskvalue[64]={'\0'};
    char buf[10]={'\0'};
    char emptyString[] = {'\0'};
    errno_t rc=-1;
    int ind =-1;

    //Initializing syscfg here
    syscfg_init();

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
                    /*SNMP set or get should not be re-enabled for XH, xfinity-open and xfinity-secure WiFi password even via RFC*/
                    if((entry->IndexValue[0].Value.uValue == 3) || 
                       (entry->IndexValue[0].Value.uValue == 4) ||
                       (entry->IndexValue[0].Value.uValue == 5) ||
                       (entry->IndexValue[0].Value.uValue == 6) ||
                       (entry->IndexValue[0].Value.uValue == 9) ||
                       (entry->IndexValue[0].Value.uValue == 10))
                    {
                        snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&emptyString, strlen(emptyString));
                    }
                    /* Get exemption for Mesh Backhaul/LnF SSIDs when SNMPPSWDCTRLFLAG is
                       false */
                    else if((entry->IndexValue[0].Value.uValue == 7) ||
                            (entry->IndexValue[0].Value.uValue == 8) ||
                            (entry->IndexValue[0].Value.uValue == 11) ||
                            (entry->IndexValue[0].Value.uValue == 12) ||
                            (entry->IndexValue[0].Value.uValue == 13) ||
                            (entry->IndexValue[0].Value.uValue == 14))
                    {
                        syscfg_get( NULL, "SNMPPSWDCTRLFLAG", buf, sizeof(buf));
                        /*  CID: 60053 -Array name cant be NULL - remove the check buf != NULL*/
                            // if SNMPPSWDCTRLFLAG == false, then Get is not allowed
                            rc =strcmp_s( "false",strlen("false"),buf,&ind);
                            ERR_CHK(rc);
                            if((!ind) && (rc == EOK))
                            {
                                snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&emptyString, strlen(emptyString));
                            }
                            else
                            {
                                getWpaPSK(entry,value);
                                snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&value, strlen(value));
                            }
                    }
                     // This parameter can't be read, but snmp was defined as read/write
                    //unsigned char value = '\0';
                    else {
                        getWpaPSK(entry,value);
                        snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)&value, strlen(value));
                    }
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
                    /*SNMP set or get should not be re-enabled for XH, xfinity-open and xfinity-secure WiFi password even via RFC*/
                    if((entry->IndexValue[0].Value.uValue == 3) || 
                       (entry->IndexValue[0].Value.uValue == 4) ||
                       (entry->IndexValue[0].Value.uValue == 5) ||
                       (entry->IndexValue[0].Value.uValue == 6) ||
                       (entry->IndexValue[0].Value.uValue == 9) ||
                       (entry->IndexValue[0].Value.uValue == 10))
                    {
                        netsnmp_request_set_error(req, SNMP_ERR_NOTWRITABLE);
                        return SNMP_ERR_GENERR;
                    }
                    /* Set exemption for Mesh Backhaul/LnF SSIDs when SNMPPSWDCTRLFLAG is
                       false */
                    else if((entry->IndexValue[0].Value.uValue == 7) ||
                            (entry->IndexValue[0].Value.uValue == 8) ||
                            (entry->IndexValue[0].Value.uValue == 11) |
                            (entry->IndexValue[0].Value.uValue == 12) |
                            (entry->IndexValue[0].Value.uValue == 13) ||
                            (entry->IndexValue[0].Value.uValue == 14))
                    {
                        syscfg_get( NULL, "SNMPPSWDCTRLFLAG", buf, sizeof(buf));
                        if( buf != NULL )
                        {
                            // if SNMPPSWDCTRLFLAG == false, Set is not allowed
                             rc =strcmp_s( "false",strlen("false"),buf,&ind);
                            ERR_CHK(rc);
                            if((!ind) && (rc == EOK))

                            {
                                netsnmp_request_set_error(req, SNMP_ERR_NOTWRITABLE);
                                return SNMP_ERR_GENERR;
                            }
                        }
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
                    /*SNMP set or get should not be re-enabled for XH, xfinity-open and xfinity-secure WiFi password even via RFC*/
                    if((entry->IndexValue[0].Value.uValue == 3) ||
                       (entry->IndexValue[0].Value.uValue == 4) ||
                       (entry->IndexValue[0].Value.uValue == 5) ||
                       (entry->IndexValue[0].Value.uValue == 6) ||
                       (entry->IndexValue[0].Value.uValue == 9) ||
                       (entry->IndexValue[0].Value.uValue == 10))
                    {
                        netsnmp_request_set_error(req, SNMP_ERR_NOTWRITABLE);
                        return SNMP_ERR_GENERR;
                    }
                    /* Set exemption for Mesh Backhaul/LnF SSIDs when SNMPPSWDCTRLFLAG is
                       false */
                    else if((entry->IndexValue[0].Value.uValue == 7) ||
                            (entry->IndexValue[0].Value.uValue == 8) ||
                            (entry->IndexValue[0].Value.uValue == 11) ||
                            (entry->IndexValue[0].Value.uValue == 12) ||
                            (entry->IndexValue[0].Value.uValue == 13) ||
                            (entry->IndexValue[0].Value.uValue == 14))
                    {
                        syscfg_get( NULL, "SNMPPSWDCTRLFLAG", buf, sizeof(buf));
                        if( buf != NULL )
                        {
                            // if SNMPPSWDCTRLFLAG == false, Set is not allowed
                            rc =strcmp_s( "false",strlen("false"),buf,&ind);
                            ERR_CHK(rc);
                            if((!ind) && (rc == EOK))
                            {
                                netsnmp_request_set_error(req, SNMP_ERR_NOTWRITABLE);
                                return SNMP_ERR_GENERR;
                            }
                        }
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


