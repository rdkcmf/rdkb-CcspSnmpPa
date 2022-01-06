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

#include "safec_lib_common.h"

#define TRUE 1
#define FALSE 0

#define IANA_ORIGIN_DM "Device.IP.Interface.1.IPv6Address.%d.Origin"
#define IANA_ORIGIN_DHCPv6 "DHCPv6"
#define IANA_ORIGIN_AUTO   "AutoConfigured"

#define IAPD_PREFIXLENGTH_SUBID 4
#define IAPD_PREFIXVALUE_SUBID 5
#define IAPD_PREFIX_DM "Device.IP.Interface.1.IPv6Prefix.%d.Prefix"
#define DEVICE_REBOOT_REASON "Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason"
#define RDKB_PAM_COMPONENT_NAME		     "eRT.com.cisco.spvtg.ccsp.pam"
#define RDKB_PAM_DBUS_PATH		     "/com/cisco/spvtg/ccsp/pam"
#define  MAX_STRVAL 64

#define MAX_INTERFACE_VAL 50
#define MAX_VAL_SET 100


static int setRebootReason(char * paramName,char * paramValue);

typedef union iapd_s {
    char prefix_value[40];
    int  prefix_length;
}iapd_t;


static int is_iana_addr(int index)
{
    char dm_str[64] = {'\0'};
    char iana_origin[32] = {'\0'};
    errno_t rc = -1;
    int ind = -1;

    rc = sprintf_s(dm_str, sizeof(dm_str), IANA_ORIGIN_DM, index);
    if(rc < EOK)
    {
            ERR_CHK(rc);
            return FALSE;
     }

    if(get_dm_value(dm_str, iana_origin, sizeof(iana_origin))) {
        AnscTraceError(("%s failed to get %s.\n", __func__, dm_str));
		CcspTraceError(("%s failed to get %s.\n", __func__, dm_str));
        return FALSE;
    }

    rc = strcmp_s(IANA_ORIGIN_DHCPv6,strlen(IANA_ORIGIN_DHCPv6) ,iana_origin, &ind);
	/* XF3-6151: Adding check for Autoconfgured ip mode */
    if (ind)
    {
		rc = strcmp_s(IANA_ORIGIN_AUTO, strlen(IANA_ORIGIN_AUTO) ,iana_origin, &ind);
    }

    ERR_CHK(rc);
     if((ind) && (rc == EOK)) 
     {
        AnscTraceError(("IANA ORIGIN \"%s\".\n", iana_origin));
		CcspTraceError(("IANA ORIGIN \"%s\".\n", iana_origin));
        return FALSE;
    }

    return TRUE;
}

static int iapd_handler(int lastOid, int insNum, iapd_t *pIapd)
{
    char dm_str[64] = {'\0'}, prefix[64] = {'\0'};
    char *pLen, *pVal;
    char *ptr = NULL;
    size_t len = 0;
    
    
    errno_t rc =-1;

    if (pIapd == NULL) {
        AnscTraceError(("%s invalid parameter.\n", __func__));
		CcspTraceError(("%s invalid parameter.\n", __func__));
        return FALSE;
    }

     rc =   sprintf_s(dm_str, sizeof(dm_str), IAPD_PREFIX_DM, insNum);
   if(rc < EOK)
   {
        ERR_CHK(rc);
        return FALSE;
   }

    if(get_dm_value(dm_str, prefix, sizeof(prefix))) {
        AnscTraceError(("%s failed to get %s.\n", __func__, dm_str));
		CcspTraceError(("%s failed to get %s.\n", __func__, dm_str));
        return FALSE;
    }

    if (lastOid == IAPD_PREFIXLENGTH_SUBID) {
        pLen = strrchr(prefix, '/');
        if (!pLen) {
            AnscTraceError(("%s wrong backend value %s.\n", __func__, prefix));
			CcspTraceError(("%s wrong backend value %s.\n", __func__, prefix));
            return FALSE;
        }else{
            pLen++; // skip '/'
            pIapd->prefix_length = atoi(pLen);
        }
    }else if (lastOid == IAPD_PREFIXVALUE_SUBID) {
        if(prefix!=NULL)
        {
           len = strlen(prefix);
        } 
        if(!len)
        {  
          return FALSE;
        }
        pVal = strtok_s(prefix,&len, "/",&ptr);
        
        if(!pVal) {
            AnscTraceError(("%s wrong backend value %s.\n", __func__, prefix));
			CcspTraceError(("%s wrong backend value %s.\n", __func__, prefix));
            return FALSE;
        }
        else
        {
            /* Covreity Fix : CID:135471:Buffer_Size_Warning */
            rc = strcpy_s(pIapd->prefix_value,sizeof(pIapd->prefix_value), pVal);
            if(rc != EOK)
              {
                     ERR_CHK(rc);
                      return FALSE;
              }
        }
    }else{
        AnscTraceError(("%s unexpected lastOid %d.\n", __func__, lastOid));
		CcspTraceError(("%s unexpected lastOid %d.\n", __func__, lastOid));
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
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info* req;
    PCCSP_TABLE_ENTRY entry = NULL; 
    int index;

    for (req = requests; req != NULL; req = req->next) {
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceError(("No entry found for IA_NA table.\n"));
			CcspTraceError(("No entry found for IA_NA table.\n"));
            continue;
        }

        index = entry->IndexValue[0].Value.iValue;
        if (is_iana_addr(index) != TRUE) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceError(("Instance number %d are not IA_NA address entry.\n", index));
			CcspTraceError(("Instance number %d are not IA_NA address entry.\n", index));
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
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info* req;
    int subid;
    PCCSP_TABLE_ENTRY entry = NULL; 
    netsnmp_variable_list *vb = NULL;
    int index;
    iapd_t iapd = {{0}};



    for (req = requests; req != NULL; req = req->next) {
        vb = req->requestvb;
        subid = vb->name[vb->name_length -2];
        entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
        if (entry == NULL) {
            netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
            AnscTraceError(("No entry found for IA_PD table.\n"));
			CcspTraceError(("No entry found for IA_PD table.\n"));
            continue;
        }

        index = entry->IndexValue[0].Value.iValue;
        
        switch (reqinfo->mode) {
        case MODE_GET:

            if ((subid == IAPD_PREFIXLENGTH_SUBID) || 
                (subid == IAPD_PREFIXVALUE_SUBID)) {
                if(iapd_handler(subid, index, &iapd) != TRUE) {
                    CcspTraceError(("iapd_handler failed.\n"));
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                    break;
                }
            }

            if (subid == IAPD_PREFIXLENGTH_SUBID){              
                CcspTraceInfo(("prefix length %d.\n", iapd.prefix_length));
                snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&iapd.prefix_length, sizeof(iapd.prefix_length));             
                req->processed = 1;

            } else if (subid == IAPD_PREFIXVALUE_SUBID){
                CcspTraceInfo(("prefix value %s.\n", iapd.prefix_value));
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
    size_t len = 0;
    errno_t rc =-1;
    int ind =-1;
    if(octet == NULL) 
        return FALSE;

    if(get_dm_value(SNMPENABLE_DM, strVal, sizeof(strVal))) 
        return FALSE;
    len = strlen(strVal);
    for(ptr=strVal; ;ptr=NULL) {
       
        if(!len)
        break;
        
        substr = strtok_s(ptr,&len, ",", &saveptr);
        if(substr == NULL) 
            break;
        
        int substr_length = strlen(substr);
      
        for(i=0; i<SNMPENABLE_MAX; i++) {
            rc = strcasecmp_s(substr,substr_length, gSnmpEnableInfo[i].str,&ind);
            ERR_CHK(rc);
            if ((!ind) && (rc == EOK))
            {
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
    char strval[MAX_STRVAL] = {'\0'};
    errno_t rc =-1;
    
   bits = ((unsigned char) octet[0]) & 0xFF;

    bzero(strval, sizeof(strval));

    for(i=0; i<SNMPENABLE_MAX; i++) {
        if(bits & gSnmpEnableInfo[i].bitmap) {
            if(j==0) 
            {
                rc = strcpy_s(strval,sizeof(strval), gSnmpEnableInfo[i].str);
                if(rc != EOK)
                   {
                    ERR_CHK(rc);
                    return FALSE;
                   }

            }
            else
            {
                rc = strcat_s(strval,sizeof(strval), ",");
                if(rc != EOK)
                   {
                    ERR_CHK(rc);
                    return FALSE;
                   }
                  /* Coverity  Fix CID:135582 STRING_OVERFLOW */
                 if( ( strlen( strval ) + strlen( gSnmpEnableInfo[i].str ))  < MAX_STRVAL ) {

                  rc =  strcat_s(strval, sizeof(strval),gSnmpEnableInfo[i].str);
                  if(rc != EOK)
                   {
                     ERR_CHK(rc);
                     return FALSE;
                    }
                }
                 else
               {
                        CcspTraceDebug((" set_snmp_enable : string len of gSnmpEnableInfo[i].str  is greater than MAX_STRVAL \n"));
               }


            }
            j++;
        }
    }

    if(set_dm_value(SNMPENABLE_DM, strval, strlen(strval))) 
        return FALSE;

    return TRUE;
}

#define FactoryReset_lastoid 1002
#define DeviceReset_lastoid 1003
#define ConfigureWiFi_lastoid 1005
#define DeviceResetMode_lastoid 1
#define FACTORY_RESET_DM 	"Device.X_CISCO_COM_DeviceControl.FactoryReset"
#define FACTORY_RESET_DM_WIFI	"Device.WiFi.X_CISCO_COM_FactoryResetRadioAndAp"

int setFactoryReset(int value)
{
    if ((value < 0) || (value > 3 )){
        return -1; /* if not true, return inconsistent value */
    }
		printf("%s ... \n",__FUNCTION__);
/*Value list: 
Call appropriate DML parameter based on the reset case 
		false(0)
		routerAndWifi(1)
		routerOnly(2)
		wifi(3)
*/
    switch(value){
	case 0 :
		break;
	case 1 :
/* Have SNMP Reset To Defaults the same way as Web GUI.
   Some devices reboot prior to completing FACTORY_RESET_DM_WIFI due to driver */
#if defined (INTEL_PUMA7)
               if (set_dm_value(FACTORY_RESET_DM, "Router,Wifi,VoIP,delay", strlen("Router,Wifi,VoIP,delay"))){
#else
               if (set_dm_value(FACTORY_RESET_DM, "Router,Wifi,VoIP", strlen("Router,Wifi,VoIP"))){
#endif
                        return -1;
                }
                break;
	case 2 :
		if (set_dm_value(FACTORY_RESET_DM, "Router", strlen("Router"))){
       			return -1;
    		}
		break;
        case 3 :
		if (set_dm_value(FACTORY_RESET_DM, "Wifi", strlen("Wifi"))){
       			return -1;
    		}
		break;
        /* CID: 69718 Dead default case in switch, value should be 0,1,2,3 */
	}
    return 0;
}

// This function is to handle WiFi only reset case
int handleDeviceMgmtParam( 
    netsnmp_mib_handler             *handler,
    netsnmp_handler_registration    *reginfo,
    netsnmp_agent_request_info      *reqinfo,
    netsnmp_request_info            *requests
)
{
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info* request;
    netsnmp_variable_list *requestvb    = NULL;
    int subid, ret;
    int value = 0;

    for (request = requests; request != NULL; request = request->next) {
         requestvb = request->requestvb;
		 subid = requestvb->name[requestvb->name_length - 2];
                 CcspTraceInfo((" subid is '%d'\n",subid));
                 
        switch(reqinfo->mode){
        case MODE_GET:
            if(subid == FactoryReset_lastoid) {
                /* always return false when get */
                value = 0;
                snmp_set_var_typed_value(request->requestvb, (u_char)ASN_INTEGER, (u_char *)&value, sizeof(value));
                request->processed = 1;
            }
            break;

	 case MODE_SET_RESERVE1:
		if(subid == ConfigureWiFi_lastoid)
		{
			CcspTraceError(("Device.DeviceInfo.X_RDKCENTRAL-COM_ConfigureWiFi is not writable\n")); 
			return SNMP_ERR_NOTWRITABLE;
		}
                ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
                if (ret != SNMP_ERR_NOERROR)
                netsnmp_set_request_error(reqinfo, requests, ret);
                request->processed = 1;     /* request->processed will be reset in every step by netsnmp_call_handlers */
                break;
	case MODE_SET_RESERVE2:
              //RDKB-6178
              if(subid == DeviceReset_lastoid){
                 if(*requestvb->val.integer== 1){
               	   CcspTraceWarning(("RDKB_ROUTER_RESET : Reset triggered for Router and Wifi\n")); 
                   //Till deployment team correct the logic for resetting Router
                   //we will set only router reset
                   *requestvb->val.integer = 2;
                  }
              }
	      
	      if(subid == DeviceResetMode_lastoid){
	       
              	setRebootReason(DEVICE_REBOOT_REASON,"snmp-reboot");
              	CcspTraceWarning(("RDKB_REBOOT : Reboot triggered through SNMP MODE Change\n")); 
              }  
	      if(subid == FactoryReset_lastoid) {
                if(*requestvb->val.integer==2 || *requestvb->val.integer==1 )
                {
                  
                CcspTraceWarning(("RDKB_REBOOT : Reboot triggered through SNMP Factory Reset\n"));
                
                }  
                if (setFactoryReset(*requestvb->val.integer)){
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


static int setRebootReason(char * paramName,char * paramValue) 
{

    parameterValStruct_t valStr;
    char str[2][MAX_VAL_SET];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
     errno_t rc =-1;
             
   rc =  sprintf_s(valStr.parameterName,MAX_VAL_SET, "%s",paramName);
   if(rc < EOK)
     {
          ERR_CHK(rc);
          return -1;
     }
   rc =  sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%s", paramValue);
     if(rc < EOK)
     {
          ERR_CHK(rc);
          return -1;
     }
    valStr.type = ccsp_string;
     
    
    if (!Cosa_SetParamValuesNoCommit(RDKB_PAM_COMPONENT_NAME, RDKB_PAM_DBUS_PATH, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

int
handleDeviceConfig(
    netsnmp_mib_handler             *handler,
    netsnmp_handler_registration    *reginfo,
    netsnmp_agent_request_info      *reqinfo,
    netsnmp_request_info            *requests
)
{
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info* request;
    netsnmp_variable_list *requestvb    = NULL;
    int subid, ret;
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
                if(set_snmp_enable((const char *)requestvb->val.string) != TRUE) {
                    CcspTraceError(("%s set failed.\n", SNMPENABLE_DM));
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

#define CONNECTEDCLIENT_DM_INTERFACE "Device.Hosts.Host.%lu.Layer1Interface"
int getInterface(PCCSP_TABLE_ENTRY pEntry, char *interface)
{
    char dmStr[128] = {'\0'};
	char index;	
	int iface;
        errno_t rc = -1;        

    if(!interface)
        return -1;

    rc = sprintf_s(dmStr, sizeof(dmStr), CONNECTEDCLIENT_DM_INTERFACE, pEntry->IndexValue[0].Value.uValue);
     if(rc < EOK)
     {
        ERR_CHK(rc);
        return -1;
     }
    
    get_dm_value(dmStr, interface, 50);
	if(strstr(interface,"WiFi")) {
		index = interface[strlen(interface)-1];
		iface = index - '0';
		if(iface == 1)
                {                  
			 rc = strcpy_s(interface,MAX_INTERFACE_VAL,"WiFi 2.4G");
                          if(rc != EOK)
                         {
                           ERR_CHK(rc);
                           return -1;
                          }
                }
		else if(iface == 2)
                {
			rc = strcpy_s(interface,MAX_INTERFACE_VAL,"WiFi 5G");
                         if(rc != EOK)
                         {
                           ERR_CHK(rc);
                           return -1;
                          }

                }
		else
                {
			rc = strcpy_s(interface,MAX_INTERFACE_VAL,"WiFi");
                        if(rc != EOK)
                         {
                           ERR_CHK(rc);
                           return -1;
                          }

                }
	}
    return 0; 
}

int
handleConnectedDevices(
    netsnmp_mib_handler             *handler,
    netsnmp_handler_registration    *reginfo,
    netsnmp_agent_request_info      *reqinfo,
    netsnmp_request_info            *requests
)
{
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info* req;
    int subid;
    PCCSP_TABLE_ENTRY entry = NULL; 
    netsnmp_variable_list *vb = NULL;
	char interface[MAX_INTERFACE_VAL] = {'\0'};

    for (req = requests; req != NULL; req = req->next) {
   
		vb = req->requestvb;
		subid = vb->name[vb->name_length -2];

		entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(req);
		if (entry == NULL) {
			netsnmp_request_set_error(req, SNMP_NOSUCHINSTANCE);
			AnscTraceWarning(("No entry found for Connected clients!\n"));
			continue;
		}
		switch (reqinfo->mode) {
			case MODE_GET:
				if(subid == 6){
					getInterface(entry, interface);
				    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, (u_char *)interface, strlen(interface));
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
