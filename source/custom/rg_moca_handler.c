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
#include "safec_lib_common.h"

// Power
#define MOCA_DM_OBJ                             "Device.MoCA.Interface."
#define MOCA_DM_TxPowerLimit                    "Device.MoCA.Interface.1.TxPowerLimit"
#define MOCA_DM_BeaconPowerLimit                "Device.MoCA.Interface.1.BeaconPowerLimit"
#define MOCA_DM_AutoPowerControlPhyRate         "Device.MoCA.Interface.1.AutoPowerControlPhyRate"

//Channel
#define MOCA_DM_FreqCurrentMaskSetting          "Device.MoCA.Interface.1.FreqCurrentMaskSetting"
#define MOCA_DM_X_CISCO_COM_ChannelScanMask     "Device.MoCA.Interface.1.X_CISCO_COM_ChannelScanMask"
#define NOT_IMPLEMENTED -2 

//Base
#define MOCA_DM_TabooMask                       "Device.MoCA.Interface.1.NodeTabooMask"

#if 0
#ifdef AnscTraceWarning
#undef AnscTraceWarning
#define AnscTraceWarning(a) printf("%s:%d> ", __FUNCTION__, __LINE__); printf a
#endif

#ifdef AnscTraceError
#undef AnscTraceError
#define AnscTraceError(a) printf("%s:%d> ", __FUNCTION__, __LINE__); printf a
#endif

#endif

#define STR_MAX 80

#define MAX_VAL_SET 100
#define MAX_VAL_LEVEL 120

// Power
static const int saMocaDevPwrTxMax_subid = 2;
static const int saMocaDevPwrCtrlPhyRate_subid = 3;
static const int saMocaDevPwrBeaconLevel_subid = 4;

// Channel
static const int saMocaDevChannelMask_subid = 3;
static const int saMocaDevChannelScanMask_subid = 4;

// Base 
static const int saMocaDevTabooMask_subid = 8;

static char *dstComp, *dstPath; /* cache */

//ccsp_string, 
//ccsp_int,
//ccsp_unsignedInt,
//ccsp_boolean,
//ccsp_dateTime,
//ccsp_base64,
//ccsp_long, 
//ccsp_unsignedLong, 
//ccsp_float, 
//ccsp_double,
//ccsp_byte, 
//ccsp_none 

static BOOL FindMoCADestComp(void)
{
    if (dstComp && dstPath)
        return TRUE;

    if (dstComp)
        AnscFreeMemory(dstComp);
    if (dstPath)
        AnscFreeMemory(dstPath);
    dstComp = dstPath = NULL;

    if (!Cosa_FindDestComp(MOCA_DM_OBJ, &dstComp, &dstPath)
            || !dstComp || !dstPath)
    {
        CcspTraceError(("%s: fail to find dest comp\n", __FUNCTION__));
        return FALSE;
    } else {
        CcspTraceInfo(("MOCA_DM_OBJ: %s dstComp: %s dstPath: %s\n", MOCA_DM_OBJ, dstComp, dstPath));
    }

    return TRUE;
}

static int getTxPowerLimit(int subid) {
    /* Coverity Fix CID:55976,64637 Uninit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[STR_MAX] = {0};
    char* name = (char *)mystring;
    int pwrTxMax = 0;
    errno_t rc =-1;

    CcspTraceInfo(("getTxPowerLimit called on subid: %d\n", subid));
    
    FindMoCADestComp();
    
    rc = sprintf_s(name, sizeof(mystring), MOCA_DM_TxPowerLimit);
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
    
    pwrTxMax = _ansc_atoi(valStr[0]->parameterValue);
    CcspTraceInfo(("pwrTxMax: %d\n", pwrTxMax));
    retval = pwrTxMax;

    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setTxPowerLimit(int value) {
    parameterValStruct_t valStr;
    char str[2][MAX_VAL_SET];
    errno_t rc = -1;
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    CcspTraceInfo(("value: %d\n", value));

    FindMoCADestComp(); /*TODO: Handle error*/

    rc = sprintf_s(valStr.parameterName,MAX_VAL_SET, MOCA_DM_TxPowerLimit);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return -1;
     }    
    
    rc = sprintf_s(valStr.parameterValue,MAX_VAL_SET, "%d", value);
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

static int getBeaconPwrLevel(int subid) {
    /* Coverity Fix  CID: 59177,60847,75006  UnInit var*/
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[STR_MAX] = {0};
    char* name = (char *)mystring;
    int beaconPwrLevel = 0;
    errno_t rc = -1;

    CcspTraceInfo(("getBeaconPwrLevel called on subid: %d\n", subid));
    
    FindMoCADestComp();
    
    rc = sprintf_s(name, sizeof(mystring), MOCA_DM_BeaconPowerLimit);
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
    
    beaconPwrLevel = -(_ansc_atoi(valStr[0]->parameterValue));
    CcspTraceInfo(("beaconPwrLevel: %d\n", beaconPwrLevel));
    retval = beaconPwrLevel;

    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setBeaconPwrLevel(int value) {
    parameterValStruct_t valStr;
    char str[2][MAX_VAL_LEVEL];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    CcspTraceInfo(("value: %d\n", value));

    FindMoCADestComp(); 
    errno_t rc =-1;

    rc = sprintf_s(valStr.parameterName,MAX_VAL_LEVEL, MOCA_DM_BeaconPowerLimit);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return -1;
     }

   rc  =   sprintf_s(valStr.parameterValue,MAX_VAL_LEVEL, "%d", -value);
   if(rc < EOK)
    {
        ERR_CHK(rc);
        return -1;
     }

    valStr.type = ccsp_unsignedInt;

    CcspTraceInfo(("dstComp: %s\n", dstComp));
    CcspTraceInfo(("dstPath: %s\n", dstPath));
    CcspTraceInfo(("valStr.parameterName: %s\n", valStr.parameterName));
    CcspTraceInfo(("valStr.parameterValue: %s\n", valStr.parameterValue));

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

static int getPwrCtrlPhyRate(int subid) {
    /* Coverity Fix CID:68029 UnInit var*/
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[STR_MAX] = {0};
    char* name = (char *)mystring;
    int controlPhyRate = 0;
  errno_t rc =-1;
    CcspTraceInfo(("getPwrCtrlPhyRate called on subid: %d\n", subid));
    
    FindMoCADestComp();
    
    rc = sprintf_s(name, sizeof(mystring), MOCA_DM_AutoPowerControlPhyRate);
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
    
    controlPhyRate = _ansc_atoi(valStr[0]->parameterValue);
    CcspTraceInfo(("controlPhyRate: %d\n", controlPhyRate));
    retval = controlPhyRate;

    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setPwrCtrlPhyRate(int value) {
    parameterValStruct_t valStr;
    char str[2][MAX_VAL_LEVEL];
    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];
    
    CcspTraceInfo(("value: %d\n", value));

    FindMoCADestComp(); 
    errno_t rc =-1;

    rc = sprintf_s(valStr.parameterName,MAX_VAL_LEVEL, MOCA_DM_AutoPowerControlPhyRate);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return -1;
     }

    rc = sprintf_s(valStr.parameterValue,MAX_VAL_LEVEL, "%d", value);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return -1;
     }

    valStr.type = ccsp_unsignedInt;

    CcspTraceInfo(("dstComp: %s\n", dstComp));
    CcspTraceInfo(("dstPath: %s\n", dstPath));
    CcspTraceInfo(("valStr.parameterName: %s\n", valStr.parameterName));
    CcspTraceInfo(("valStr.parameterValue: %s\n", valStr.parameterValue));

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

int
handleMocaDevicePower(
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
netsnmp_variable_list *vb = NULL;

for (req = requests; req != NULL; req = req->next)
{
    vb = req->requestvb;
    subid = vb->name[vb->name_length -2];

    switch (reqinfo->mode) {
        case MODE_GET:
        
            if(subid == saMocaDevPwrTxMax_subid) {
                intval = getTxPowerLimit(subid);

                if (intval >= 0) {
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&intval, sizeof(intval));
                    req->processed = 1;
                    CcspTraceInfo(("saMocaDevicePower, retrieved value %d\n", intval));
                }

            } else if (subid == saMocaDevPwrBeaconLevel_subid) {
                intval = getBeaconPwrLevel(subid);

                if (intval <= 0) {
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&intval, sizeof(intval));
                    req->processed = 1;
                    CcspTraceInfo(("saMocaDevicePower, retrieved value %d\n", intval));
                }

            } else if (subid == saMocaDevPwrCtrlPhyRate_subid) {
                intval = getPwrCtrlPhyRate(subid);

                if (intval >= 0) {
                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_INTEGER, (u_char *)&intval, sizeof(intval));
                    req->processed = 1;
                    CcspTraceInfo(("saMocaDevicePower, retrieved value %d\n", intval));
                }
            }

            break;

        case MODE_SET_RESERVE1:
        /* sanity check */
            if (subid == saMocaDevPwrTxMax_subid) {
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, retval);

                    CcspTraceError(("MODE_SET_RESERVE1: incorrect type for value: %lu\n", *(vb->val.integer)));
                    CcspTraceWarning(("MODE_SET_RESERVE1: should be ASN_INTEGER\n"));

                } else if ( *(vb->val.integer) > 10 || *(vb->val.integer) < 0) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;

                    CcspTraceError(("MODE_SET_RESERVE1: incorrect range for value: %lu\n", *(vb->val.integer)));
                    CcspTraceWarning(("MODE_SET_RESERVE1: valid range is 0 - 10\n"));
                }
                
                req->processed = 1;

            } else if (subid == saMocaDevPwrCtrlPhyRate_subid) {
    
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, retval);

                    CcspTraceError(("MODE_SET_RESERVE1: incorrect type for value: %lu\n", *(vb->val.integer)));
                    CcspTraceWarning(("MODE_SET_RESERVE1: should be ASN_INTEGER\n"));

                } else if ( *(vb->val.integer) > 235 || *(vb->val.integer) < 0) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;

                    CcspTraceError(("MODE_SET_RESERVE1: incorrect range for value: %lu\n", *(vb->val.integer)));
                    CcspTraceWarning(("MODE_SET_RESERVE1: valid range is 0 - 235\n"));
                }
                
                req->processed = 1;

            } else if (subid == saMocaDevPwrBeaconLevel_subid) {
    
                if ((retval=netsnmp_check_vb_type(req->requestvb, ASN_INTEGER))!=SNMP_ERR_NOERROR){
                    netsnmp_set_request_error(reqinfo, req, retval);

                    CcspTraceError(("MODE_SET_RESERVE1: incorrect type for value: %lu\n", *(vb->val.integer)));
                    CcspTraceWarning(("MODE_SET_RESERVE1: should be ASN_INTEGER\n"));

                } else if ( *(vb->val.integer) > 0 || *(vb->val.integer) < -9) {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_BADVALUE);
                    retval = SNMP_ERR_BADVALUE;

                    CcspTraceError(("MODE_SET_RESERVE1: incorrect range for value: %lu\n", *(vb->val.integer)));
                    CcspTraceWarning(("MODE_SET_RESERVE1: valid values are 0, -3, -6, -9\n"));
                }
                
                req->processed = 1;
            }

            /* request->processed will be reset in every step by netsnmp_call_handlers */
            break;

        case MODE_SET_RESERVE2:
        /* set value to backend with no commit */
            intval = 0;
            if(subid == saMocaDevPwrTxMax_subid) {
                intval = setTxPowerLimit(*(vb->val.integer));
                req->processed = 1;

            } else if (subid == saMocaDevPwrBeaconLevel_subid) {
                intval = setBeaconPwrLevel(*(vb->val.integer));
                req->processed = 1;

            } else if (subid == saMocaDevPwrCtrlPhyRate_subid) {
                intval = setPwrCtrlPhyRate(*(vb->val.integer));
                req->processed = 1;
            }
            
            if (intval) {
                netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                retval = SNMP_ERR_GENERR;
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

#define kMin_FreqIndex 3
#define kMax_FreqIndex 25
#define kMax_FreqIndexValue 33

struct saMocaFrequencies {
                 char *psFrequency;
                 int bit;
                 uint frequency;
               };

static struct saMocaFrequencies saMocaFrequencies_list[kMax_FreqIndex] = {
    {"invalid",     0, 0},
    {"invalid",     1, 0},
    {"invalid",     2, 0},
    {"f1500(3)",    3, 1500},
    {"f1475(4)",    4, 1475},
    {"f1450(5)",    5, 1450},
    {"f1425(6)",    6, 1425},
    {"f1400(7)",    7, 1400},
    {"f1375(8)",    8, 1375},
    {"f1350(9)",    9, 1350},
    {"f1325(10)",  10, 1325},
    {"f1300(11)",  11, 1300},
    {"f1275(12)",  12, 1275},
    {"f1250(13)",  13, 1250},
    {"f1225(14)",  14, 1225},
    {"f1200(15)",  15, 1200},
    {"f1175(16)",  16, 1175},
    {"f1150(17)",  17, 1150},
    {"f1125(18)",  18, 1125}
};

static void freqMaskToBinaryStr(int freqCurrentMaskSetting, char * pvalue)
{
    int i;
    int mask = freqCurrentMaskSetting;

    CcspTraceInfo(("freqCurrentMaskSetting: %08x\n", freqCurrentMaskSetting));

    pvalue[32] = '\0';

    for(i=0; i < 32; i++) {

        mask = freqCurrentMaskSetting & (1<<i);

        if(mask) {
            pvalue[31-i] = '1';

        } else {
            pvalue[31-i] = '0';

        }
    }

    pvalue[24] = '\0';
    CcspTraceInfo(("pvalue: %s\n", pvalue));
}

static int32_t freqMaskToValue(uint32_t mask)
{
    int i;
    int32_t freq = 0;

    /* CID: 64030 Bad bit shift operation*/
    for(i=0; i < 32; i++) {
        if(mask & (1<<i)) {
            freq += 800 + 25 * i;
        }
    }

    return freq;
}

static int getFreqCurrentMaskSetting(char * pvalue) {
    /* Coverity Fix  CID: 56074,61784  UnInit var*/
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[STR_MAX] = {0};
    char* name = (char *)mystring;
    uint freqCurrentMaskSetting = 0;
    uint freq_mask = 0;
    int freq;
    int i, j;
    errno_t rc =-1;
   
    FindMoCADestComp();
    
    rc = sprintf_s(name, sizeof(mystring), MOCA_DM_FreqCurrentMaskSetting);
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
    
    CcspTraceInfo(("valStr[0]->parameterValue: %s\n", valStr[0]->parameterValue));
    sscanf(valStr[0]->parameterValue, "%016x", &freq_mask);
    CcspTraceInfo(("freq_mask: %08x\n", freq_mask));

    for (i=0; i < 31; i++) {

        if(freq_mask & (1<<i)) {

            freq = freqMaskToValue((freq_mask & (1<<i)));
            CcspTraceWarning(("freq: %d\n", freq));

            for(j=0; j<kMax_FreqIndex; j++) {

                if((int)saMocaFrequencies_list[j].frequency == freq) {
                    CcspTraceInfo(("psFrequency: %s\n", saMocaFrequencies_list[j].psFrequency));
                    CcspTraceInfo(("frequency: %d\n", saMocaFrequencies_list[j].frequency));

                    freqCurrentMaskSetting |= (1 << (31 - saMocaFrequencies_list[j].bit));
                    CcspTraceInfo(("freqCurrentMaskSetting: %08x\n", freqCurrentMaskSetting));
                }
            }
        }
    }

    freqMaskToBinaryStr(freqCurrentMaskSetting, pvalue);
    retval = freqCurrentMaskSetting;

    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setFreqCurrentMaskSetting(char * pvalue, int val_len) {
    parameterValStruct_t valStr;
    char str[2][MAX_VAL_LEVEL];
    uint bitmask = 0;
    int i;
    BOOL err = FALSE;
    errno_t rc = -1;

    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];

    CcspTraceInfo(("pvalue: %s\n", pvalue));

    FindMoCADestComp(); 

    for(i=0; i<val_len; i++) {

        if(pvalue[i] == '1') {
            bitmask |= (1 << (31 - saMocaFrequencies_list[i].bit));

            CcspTraceInfo(("pvalue[%d]: %c\n", i, pvalue[i]));
            CcspTraceInfo(("bitmask: %08x\n", bitmask));
            CcspTraceInfo(("freq: %d\n", saMocaFrequencies_list[i].frequency));

        } else if (pvalue[i] != '0') {

            CcspTraceError(("Invalid bitmask passed from user: pvalue[%d]: %c\n", i, pvalue[i]));
            err = TRUE;
            break;
        }
    }

    if(!err) {
        rc = sprintf_s(valStr.parameterName,MAX_VAL_LEVEL, "%s", MOCA_DM_FreqCurrentMaskSetting);
        if(rc < EOK)
        {
          ERR_CHK(rc);
          return -1;
        }

        
        rc =  sprintf_s(valStr.parameterValue,MAX_VAL_LEVEL, "%016x", bitmask);
        if(rc < EOK)
        {
          ERR_CHK(rc);
          return -1;
         }

        valStr.type = ccsp_string;
    
        CcspTraceInfo(("valStr.parameterName: %s\n", valStr.parameterName));
        CcspTraceInfo(("valStr.parameterValue: %s\n", valStr.parameterValue));
    
        if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
        {
            CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
            return -1;
        }
    }

    return err;
}

static int getX_CISCO_COM_ChannelScanMask(char * pvalue) {
    /* Coverity Fix CID:64441,67200 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval = 0;
    char mystring[STR_MAX]= {0};
    char* name = (char *)mystring;
    uint X_CISCO_COM_ChannelScanMask = 0;
    uint scan_mask = 0;
    int freq;
    int i, j;
    errno_t rc =-1;
   
    FindMoCADestComp();
    
    rc = sprintf_s(name, sizeof(mystring), MOCA_DM_X_CISCO_COM_ChannelScanMask);
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
    
    CcspTraceInfo(("valStr[0]->parameterValue: %s\n", valStr[0]->parameterValue));
    sscanf(valStr[0]->parameterValue, "%016x", &scan_mask);
    CcspTraceInfo(("scan_mask: %08x\n", scan_mask));

    for (i=0; i < 31; i++) {

        if(scan_mask & (1<<i)) {

            freq = freqMaskToValue((scan_mask & (1<<i)));
            CcspTraceInfo(("freq: %d\n", freq));

            for(j=0; j<kMax_FreqIndex; j++) {

                if((int)saMocaFrequencies_list[j].frequency == freq) {
                    CcspTraceInfo(("psFrequency: %s\n", saMocaFrequencies_list[j].psFrequency));
                    CcspTraceInfo(("frequency: %d\n", saMocaFrequencies_list[j].frequency));

                    X_CISCO_COM_ChannelScanMask |= (1 << (31 - saMocaFrequencies_list[j].bit));
                    CcspTraceInfo(("X_CISCO_COM_ChannelScanMask: %08x\n", X_CISCO_COM_ChannelScanMask));
                }
            }
        }
    }

    freqMaskToBinaryStr(X_CISCO_COM_ChannelScanMask, pvalue);
    retval = X_CISCO_COM_ChannelScanMask;

    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setX_CISCO_COM_ChannelScanMask(char * pvalue, int val_len) {
    parameterValStruct_t valStr;
    char str[2][MAX_VAL_LEVEL];
    uint bitmask = 0;;
    int i;
    BOOL err = FALSE;

    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];

    CcspTraceInfo(("pvalue: %s\n", pvalue));

    FindMoCADestComp(); 
    errno_t rc =-1;

    for(i=0; i<val_len; i++) {

        if(pvalue[i] == '1') {
            bitmask |= (1 << (31 - saMocaFrequencies_list[i].bit));

            CcspTraceInfo(("pvalue[%d]: %c\n", i, pvalue[i]));
            CcspTraceInfo(("bitmask: %08x\n", bitmask));
            CcspTraceInfo(("freq: %d\n", saMocaFrequencies_list[i].frequency));

        } else if (pvalue[i] != '0') {

            CcspTraceError(("Invalid bitmask passed from user: pvalue[%d]: %c\n", i, pvalue[i]));
            err = TRUE;
            break;
        }
    }

    if(!err) {
        rc = sprintf_s(valStr.parameterName,MAX_VAL_LEVEL, "%s", MOCA_DM_X_CISCO_COM_ChannelScanMask);
        if(rc < EOK)
         {
           ERR_CHK(rc);
            return -1;
          }

        rc = sprintf_s(valStr.parameterValue,MAX_VAL_LEVEL, "%016x", bitmask);
        if(rc < EOK)
         {
           ERR_CHK(rc);
            return -1;
          }

        valStr.type = ccsp_string;
    
        CcspTraceInfo(("valStr.parameterName: %s\n", valStr.parameterName));
        CcspTraceInfo(("valStr.parameterValue: %s\n", valStr.parameterValue));
    
        if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
        {
            CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
            return -1;
        }
    }

    return err;
}

#define kMax_AsnTypes   4

struct _asn_types {
                 int asn_type;
                 char *ptype;
               };

static struct _asn_types asn_types[kMax_AsnTypes] = {
    {ASN_BOOLEAN   ,"ASN_BOOLEAN"},   
    {ASN_INTEGER   ,"ASN_INTEGER"},   
    {ASN_BIT_STR   ,"ASN_BIT_STR"},   
    {ASN_OCTET_STR ,"ASN_OCTET_STR"} 
};

int
handleMocaDeviceChannel(
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
netsnmp_variable_list *vb = NULL;

for (req = requests; req != NULL; req = req->next)
{
    vb = req->requestvb;
    subid = vb->name[vb->name_length -2];
    int i;
    char strval[kMax_FreqIndexValue];

    switch (reqinfo->mode) {
        case MODE_GET:
        
            if(subid == saMocaDevChannelMask_subid) {

                intval = getFreqCurrentMaskSetting((char *)&strval);

                if (intval >= 0) {

                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, 
                                             (u_char *)&strval, strlen(strval));

                    CcspTraceInfo(("intval %08x\n", intval));
                    CcspTraceInfo(("strval %s\n", strval));

                    req->processed = 1;
                }

            } else if(subid == saMocaDevChannelScanMask_subid) {

                intval = getX_CISCO_COM_ChannelScanMask((char *)&strval);

                if (intval >= 0) {

                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, 
                                             (u_char *)&strval, strlen(strval));

                    CcspTraceInfo(("intval %08x\n", intval));
                    CcspTraceInfo(("strval %s\n", strval));

                    req->processed = 1;
                }
            }

            break;

        case MODE_SET_RESERVE1:
        /* sanity check */
            if ((subid == saMocaDevChannelMask_subid) || (subid == saMocaDevChannelScanMask_subid)) {

                for(i=0; i<kMax_AsnTypes; i++) {

                    CcspTraceInfo(("checking for type %s type: %02x\n", 
                                      asn_types[i].ptype, asn_types[i].asn_type));
   
                    retval = netsnmp_check_vb_type(req->requestvb, asn_types[i].asn_type);
                    if(retval != SNMP_ERR_NOERROR) {
                        CcspTraceWarning(("Not %s type\n", asn_types[i].ptype));
                    } else {
                        CcspTraceWarning(("type is %s\n", asn_types[i].ptype));
                    }
                }
                
                req->processed = 1;
            } 

            /* request->processed will be reset in every step by netsnmp_call_handlers */
            break;

        case MODE_SET_RESERVE2:
        /* set value to backend with no commit */
            intval = 0;
            if(subid == saMocaDevChannelMask_subid) {

                CcspTraceInfo(("val.string %s\n", req->requestvb->val.string));
                CcspTraceInfo(("val_len %d\n", req->requestvb->val_len));

                if(req->requestvb->val_len < kMax_FreqIndex) {
                    intval = setFreqCurrentMaskSetting((char *)req->requestvb->val.string, 
                                                       req->requestvb->val_len);
                    if(intval < 0) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                    }

                } else {

                    CcspTraceWarning(("val_len %d exceeds max: %d\n", 
                                      req->requestvb->val_len, kMax_FreqIndex-1));

                    netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                }

                req->processed = 1;

            } else if (subid == saMocaDevChannelScanMask_subid) {

                CcspTraceInfo(("val.string %s\n", req->requestvb->val.string));
                CcspTraceInfo(("val_len %d\n", req->requestvb->val_len));

                if(req->requestvb->val_len < kMax_FreqIndex) {
                    intval = setX_CISCO_COM_ChannelScanMask((char *)req->requestvb->val.string, 
                                                       req->requestvb->val_len);
                    if(intval < 0) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                    }

                } else {

                    CcspTraceWarning(("val_len %d exceeds max: %d\n", 
                                      req->requestvb->val_len, kMax_FreqIndex-1));

                    netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                }

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
static int getTabooMaskSetting(char * pvalue) {
    /* Coverity Fix CID: 62031,67046 UnInit var*/
    parameterValStruct_t **valStr = NULL;
    int nval = 0, retval= 0;
    char mystring[STR_MAX] = {0};
    char* name = (char *)mystring;
    uint freqCurrentMaskSetting = 0;
    uint freq_mask = 0;
    int freq;
    int i, j;
    errno_t rc =-1;
   
    FindMoCADestComp();
    
    rc = sprintf_s(name, sizeof(mystring), MOCA_DM_TabooMask);
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
    
    CcspTraceInfo(("valStr[0]->parameterValue: %s\n", valStr[0]->parameterValue));
    sscanf(valStr[0]->parameterValue, "%016x", &freq_mask);
    CcspTraceInfo(("freq_mask: %08x\n", freq_mask));

    for (i=0; i < 31; i++) {

        if(freq_mask & (1<<i)) {

            freq = freqMaskToValue((freq_mask & (1<<i)));
            CcspTraceInfo(("freq: %d\n", freq));

            for(j=0; j<kMax_FreqIndex; j++) {

                if((int)saMocaFrequencies_list[j].frequency == freq) {
                    CcspTraceInfo(("psFrequency: %s\n", saMocaFrequencies_list[j].psFrequency));
                    CcspTraceInfo(("frequency: %d\n", saMocaFrequencies_list[j].frequency));

                    freqCurrentMaskSetting |= (1 << (31 - saMocaFrequencies_list[j].bit));
                    CcspTraceInfo(("freqCurrentMaskSetting: %08x\n", freqCurrentMaskSetting));
                }
            }
        }
    }

    freqMaskToBinaryStr(freqCurrentMaskSetting, pvalue);
    retval = freqCurrentMaskSetting;

    Cosa_FreeParamValues(nval, valStr);
    
    return retval;
}

static int setTabooMaskSetting(char * pvalue, int val_len) {
    parameterValStruct_t valStr;
    char str[2][MAX_VAL_LEVEL];
    uint bitmask = 0;
    int i;
    BOOL err = FALSE;
    errno_t rc =-1;

    valStr.parameterName=str[0];
    valStr.parameterValue=str[1];

    CcspTraceInfo(("pvalue: %s\n", pvalue));

    FindMoCADestComp(); 

    for(i=0; i<val_len; i++) {

        if(pvalue[i] == '1') {
            bitmask |= (1 << (31 - saMocaFrequencies_list[i].bit));

            CcspTraceInfo(("pvalue[%d]: %c\n", i, pvalue[i]));
            CcspTraceInfo(("bitmask: %08x\n", bitmask));
            CcspTraceInfo(("freq: %d\n", saMocaFrequencies_list[i].frequency));

        } else if (pvalue[i] != '0') {

            CcspTraceError(("Invalid bitmask passed from user: pvalue[%d]: %c\n", i, pvalue[i]));
            err = TRUE;
            break;
        }
    }

    if(!err) {
       rc = sprintf_s(valStr.parameterName,MAX_VAL_LEVEL, "%s", MOCA_DM_TabooMask);
       if(rc < EOK)
    {
          ERR_CHK(rc);
          return -1;
    }

      rc =  sprintf_s(valStr.parameterValue,MAX_VAL_LEVEL, "%016x", bitmask);
       if(rc < EOK)
    {
          ERR_CHK(rc);
          return -1;
    }

        valStr.type = ccsp_string;
    
        CcspTraceInfo(("valStr.parameterName: %s\n", valStr.parameterName));
        CcspTraceInfo(("valStr.parameterValue: %s\n", valStr.parameterValue));
    
        if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
        {
            CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
            return -1;
        }
    }

    return err;
}

int
handleMocaDeviceBase(
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
netsnmp_variable_list *vb = NULL;

for (req = requests; req != NULL; req = req->next)
{
    vb = req->requestvb;
    subid = vb->name[vb->name_length -2];
    int i;
    char strval[kMax_FreqIndexValue];

    switch (reqinfo->mode) {
        case MODE_GET:
        
            if(subid == saMocaDevTabooMask_subid) {

                intval = getTabooMaskSetting((char *)&strval);

                if (intval >= 0) {

                    snmp_set_var_typed_value(req->requestvb, (u_char)ASN_OCTET_STR, 
                                             (u_char *)&strval, strlen(strval));

                    CcspTraceInfo(("intval %08x\n", intval));
                    CcspTraceInfo(("strval %s\n", strval));

                    req->processed = 1;
                }

            } 

            break;

        case MODE_SET_RESERVE1:
        /* sanity check */
            if (subid == saMocaDevTabooMask_subid) {

                for(i=0; i<kMax_AsnTypes; i++) {

                    CcspTraceInfo(("checking for type %s type: %02x\n", 
                                      asn_types[i].ptype, asn_types[i].asn_type));
   
                    retval = netsnmp_check_vb_type(req->requestvb, asn_types[i].asn_type);
                    if(retval != SNMP_ERR_NOERROR) {
                        CcspTraceWarning(("Not %s type\n", asn_types[i].ptype));
                    } else {
                        CcspTraceWarning(("type is %s\n", asn_types[i].ptype));
                    }
                }
                
                req->processed = 1;
            } 

            /* request->processed will be reset in every step by netsnmp_call_handlers */
            break;

        case MODE_SET_RESERVE2:
        /* set value to backend with no commit */
            intval = 0;
            if(subid == saMocaDevTabooMask_subid) {

                CcspTraceInfo(("val.string %s\n", req->requestvb->val.string));
                CcspTraceInfo(("val_len %d\n", req->requestvb->val_len));

                if(req->requestvb->val_len < kMax_FreqIndex) {
                    intval = setTabooMaskSetting((char *)req->requestvb->val.string, 
                                                       req->requestvb->val_len);
                    if(intval < 0) {
                        netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                    }

                } else {

                    CcspTraceWarning(("val_len %d exceeds max: %d\n", 
                                      req->requestvb->val_len, kMax_FreqIndex-1));

                    netsnmp_request_set_error(req, SNMP_ERR_GENERR);
                }

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
