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
#include <stdio.h>
#include "ansc_platform.h"
#include "cosa_api.h"
#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "net-snmp/agent/net-snmp-agent-includes.h"
#include "safec_lib_common.h"

#define NUM_NTPSERV             3
#define NUM_ETHPORTS            4

#define NTPSERV_DM_OBJ          "Device.Time."
#define NTPSERV_DM_OBJ_NAME     "com.cisco.spvtg.ccsp.pam.Name"
#define NTPSERV_DM_PARAM_PAT    "Device.Time.NTPServer%d"

#define PORTMODE_DM_OBJ         "Device.X_CISCO_COM_DeviceControl."
#define PORTMODE_DM_OBJ_NAME    "com.cisco.spvtg.ccsp.pam.Name"
#define PORTMODE_DM_PARAM_PAT   "Device.X_CISCO_COM_DeviceControl.XHSEthernetPortEnable"

typedef void (* CCSP_CLEAN_MIB_VAL_QUEUE_FUN_PTR)(void *);

struct NTPServer 
{
	CCSP_CLEAN_MIB_VAL_QUEUE_FUN_PTR CleanMibValueQueueFunctionPtr;
    int     ins;            /* instance number */
    char    dmName[1024];   /* path name of DM param */
    char    server[64];     /* hostname or ipaddress */

    /* for extension */
};

static char *dstComp, *dstPath; /* cache */

static BOOL FindNtpServerDestComp(void)
{
    if (dstComp && dstPath)
        return TRUE;

    if (dstComp)
        AnscFreeMemory(dstComp);
    if (dstPath)
        AnscFreeMemory(dstPath);
    dstComp = dstPath = NULL;
 
    if (!Cosa_FindDestComp(NTPSERV_DM_OBJ_NAME, &dstComp, &dstPath)
            || !dstComp || !dstPath)
    {
        CcspTraceError(("%s: fail to find dest comp\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

static BOOL GetNtpServer(struct NTPServer *ntpServ)
{
    /* Coverity Fix : CID 57265, 58018,63204  UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0;
    char *name[1];
    errno_t rc = -1;

    name[0] = ntpServ->dmName;
    if (!Cosa_GetParamValues(dstComp, dstPath, name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, ntpServ->dmName));
        return FALSE;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return FALSE;
    }

    rc = sprintf_s(ntpServ->server, sizeof(ntpServ->server), "%s", valStr[0]->parameterValue);
    if(rc < EOK)
     {
           ERR_CHK(rc);
           return FALSE;
      }
    Cosa_FreeParamValues(nval, valStr);

    return TRUE;
}

static BOOL SetNtpServer(struct NTPServer *ntpServ)
{
    parameterValStruct_t valStr;

    valStr.parameterName = ntpServ->dmName;
    valStr.parameterValue = ntpServ->server;
    valStr.type = ccsp_string;

    if (!Cosa_SetParamValuesNoCommit(dstComp, dstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, ntpServ->dmName));
        return FALSE;
    }

    return TRUE;
}

static BOOL CommitNtpServer(void)
{
    if (!Cosa_SetCommit(dstComp, dstPath, TRUE))
    {
        CcspTraceError(("%s: fail to commit\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

static BOOL RollbackNtpServer(void)
{
    if (!Cosa_SetCommit(dstComp, dstPath, FALSE))
    {
        CcspTraceError(("%s: fail to rollback\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

static void CleanupTableRow(netsnmp_tdata *table)
{
    netsnmp_tdata_row *row;

	while ((row = netsnmp_tdata_row_first(table)) != NULL)
        netsnmp_tdata_remove_and_delete_row(table, row);
}

static int LoadNtpServTable(netsnmp_tdata *table)
{
    int i;
    netsnmp_tdata_row *row;
    struct NTPServer *ntpServ;
    errno_t rc =-1;
    if (!table)
        return FALSE;

    for (i = 0; i < NUM_NTPSERV; i++)
    {
        if ((ntpServ = AnscAllocateMemory(sizeof(struct NTPServer))) == NULL)
            goto errout;

        rc = memset_s(ntpServ,sizeof(struct NTPServer), 0, sizeof(struct NTPServer));
        ERR_CHK(rc);
        ntpServ->CleanMibValueQueueFunctionPtr = NULL;        
        ntpServ->ins = i + 1;
        rc = sprintf_s(ntpServ->dmName, sizeof(ntpServ->dmName), NTPSERV_DM_PARAM_PAT, ntpServ->ins);
         if(rc < EOK)
         {
                ERR_CHK(rc);
                goto errout;
          }
        if ((row = netsnmp_tdata_create_row()) == NULL)
        {
            AnscFreeMemory(ntpServ);
            goto errout;
        }

        row->data = ntpServ;
        netsnmp_tdata_row_add_index(row, ASN_UNSIGNED, &ntpServ->ins, sizeof(ntpServ->ins));
        netsnmp_tdata_add_row(table, row);
    }

    return TRUE;

errout:
    CleanupTableRow(table);
    return FALSE;
}

int NtpServer_HandleRequest(netsnmp_mib_handler *handler,
        netsnmp_handler_registration *reginfo,
        netsnmp_agent_request_info *reqinfo,
        netsnmp_request_info *requests)
{
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info        *req;
    struct NTPServer            *ntpServ;
    int                         ret, ncp;
    errno_t rc =-1;

    switch (reqinfo->mode) {
    case MODE_GET:
        for (req = requests; req != NULL; req = req->next)
        {
            if ((ntpServ = netsnmp_tdata_extract_entry(req)) == NULL)
            {
                netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHINSTANCE);
                continue;
            }

            if (!GetNtpServer(ntpServ))
            {
                netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                break;
            }

            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                    ntpServ->server, strlen(ntpServ->server));

            req->processed = 1;
        }
        break;

    case MODE_SET_RESERVE1:
        /* sanity check */
        for (req = requests; req != NULL; req = req->next)
        {
            if ((ntpServ = netsnmp_tdata_extract_entry(req)) == NULL)
            {
                netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHINSTANCE);
                continue;
            }

            ret = netsnmp_check_vb_type_and_max_size(req->requestvb, 
                    ASN_OCTET_STR, sizeof(ntpServ->server) - 1);
            if (ret != SNMP_ERR_NOERROR)
            {
                netsnmp_set_request_error(reqinfo, req, ret);
                return SNMP_ERR_NOERROR;
            }
        }
        break;

    case MODE_SET_RESERVE2:
        /* set value to backend with no commit */
        for (req = requests; req != NULL; req = req->next)
        {
            if ((ntpServ = netsnmp_tdata_extract_entry(req)) == NULL)
            {
                netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHINSTANCE);
                continue;
            }

            /**
             * we couldn't assume "requestvb.val.string" is ascii string ('\0' ended)
             * so do not use snprintf/strncpy directly.
             */
            rc = memset_s(ntpServ->server,sizeof(ntpServ->server), 0, sizeof(ntpServ->server));
            ERR_CHK(rc);
            ncp = req->requestvb->val_len > sizeof(ntpServ->server) - 1 ?
                sizeof(ntpServ->server) - 1 : req->requestvb->val_len;
           rc =  strncpy_s(ntpServ->server,sizeof(ntpServ->server), (char *)req->requestvb->val.string,(unsigned int)ncp);
           if(rc != EOK)
           {
                 ERR_CHK(rc);
                 return SNMP_ERR_GENERR;;
            }
           
           

            if (!SetNtpServer(ntpServ))
            {
                netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                break;
            }

            req->processed = 1;
        }
 
        break;

    case MODE_SET_ACTION:
        /* commit */
        if (!CommitNtpServer())
            return SNMP_ERR_GENERR;

        for (req = requests; req != NULL; req = req->next)
            req->processed = 1;

        break;

    case MODE_SET_FREE:
        if (!RollbackNtpServer())
            return SNMP_ERR_GENERR;
        break;

    case MODE_SET_COMMIT:
    case MODE_SET_UNDO:
        /* nothing */
        break;

    default:
        netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

int
NtpServer_RefreshCache(netsnmp_tdata *table)
{
    if (!FindNtpServerDestComp())
        return -1;

    if (!LoadNtpServTable(table))
        return -1;

    return 0;
}










//-----------------------------------------------------------------------------------
struct PortMode 
{
    int     ins;            /* instance number */
    long    bValue;      /*Value for XHS mode*/
    CCSP_CLEAN_MIB_VAL_QUEUE_FUN_PTR CleanMibValueQueueFunctionPtr;
    /* for extension */
};

static char *PMdstComp, *PMdstPath; /* cache */

static BOOL FindPortModeDestComp(void)
{
    if (PMdstComp && PMdstPath)
        return TRUE;

    if (PMdstComp)
        AnscFreeMemory(PMdstComp);
    if (PMdstPath)
        AnscFreeMemory(PMdstPath);
    PMdstComp = PMdstPath = NULL;
    
    if (!Cosa_FindDestComp(PORTMODE_DM_OBJ_NAME, &PMdstComp, &PMdstPath)
            || !PMdstComp || !PMdstPath)
    {
        CcspTraceError(("%s: fail to find dest comp\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

static BOOL GetPortMode(struct PortMode *portMode)
{
    /* Coverity Fix CID : 66548 UnInit var */
    parameterValStruct_t **valStr = NULL;
    int nval = 0;
    char *name[1];
    errno_t rc =-1;
    int ind =-1;
    
    if (portMode->ins != 4) {
        portMode->bValue = 0;
        return 0;
    }

    name[0] = PORTMODE_DM_PARAM_PAT;
    if (!Cosa_GetParamValues(PMdstComp, PMdstPath, name, 1, &nval, &valStr))
    {
        CcspTraceError(("%s: fail to get: %s\n", __FUNCTION__, name[0]));
        return -1;
    }

    if (nval < 1)
    {
        CcspTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return -1;
    }

    
      rc = strcasecmp_s( "true",strlen("true"),valStr[0]->parameterValue,&ind);
      ERR_CHK(rc);
      if ( ((valStr[0]->parameterValue[0] =='1') && (valStr[0]->parameterValue[1] =='\0')) 
           || ( (rc == EOK) && (!ind) ))  
     {   
        portMode->bValue = 1;
     }
    else
        portMode->bValue = 0;
    
    Cosa_FreeParamValues(nval, valStr);

    return 0;
}

static BOOL SetPortMode(struct PortMode *portMode)
{
    parameterValStruct_t valStr;
    
    if (portMode->ins != 4) return -1;

    valStr.parameterName = PORTMODE_DM_PARAM_PAT;
    valStr.parameterValue = portMode->bValue ? "true" : "false";
    valStr.type = ccsp_boolean;

    if (!Cosa_SetParamValuesNoCommit(PMdstComp, PMdstPath, &valStr, 1))
    {
        CcspTraceError(("%s: fail to set: %s\n", __FUNCTION__, valStr.parameterName));
        return -1;
    }

    return 0;
}

static BOOL CommitPortMode(void)
{
    //printf("COMMITTING PORT MODE\n"); fflush(stdout);
    if (!Cosa_SetCommit(PMdstComp, PMdstPath, TRUE))
    {
        //printf("COMMITTING PORT MODE FAILURE\n"); fflush(stdout);
        CcspTraceError(("%s: fail to commit\n", __FUNCTION__));
        return FALSE;
    }
    //printf("COMMITTING PORT MODE SUCCESS\n"); fflush(stdout);

    return TRUE;
}

static BOOL RollbackPortMode(void)
{
    if (!Cosa_SetCommit(PMdstComp, PMdstPath, FALSE))
    {
        CcspTraceError(("%s: fail to rollback\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}


int LanPortMode_HandleRequest(netsnmp_mib_handler *handler,
        netsnmp_handler_registration *reginfo,
        netsnmp_agent_request_info *reqinfo,
        netsnmp_request_info *requests)
{
    UNREFERENCED_PARAMETER(handler);
    UNREFERENCED_PARAMETER(reginfo);
    netsnmp_request_info        *req;
    struct PortMode            *portMode;
    int                         ret;
    netsnmp_variable_list *vb = NULL;
    int subid;

    switch (reqinfo->mode) {
    case MODE_GET:
        for (req = requests; req != NULL; req = req->next)
        {
            vb = req->requestvb;
            subid = vb->name[vb->name_length -2];
            if ((portMode = netsnmp_tdata_extract_entry(req)) == NULL)
            {
                netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHINSTANCE);
                continue;
            }
            
            if (subid == 1) {
                snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                    &portMode->ins, sizeof(portMode->ins));
            } else {
                if (GetPortMode(portMode))
                {
                    netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                    break;
                }
                
            
                snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                    &portMode->bValue, sizeof(portMode->bValue));
            }

            req->processed = 1;
        }
        break;

    case MODE_SET_RESERVE1:
        /* sanity check */
        for (req = requests; req != NULL; req = req->next)
        {
            req->processed = 1;
            if ((portMode = netsnmp_tdata_extract_entry(req)) == NULL)
            {
                netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHINSTANCE);
                continue;
            }

            ret = netsnmp_check_vb_type_and_max_size(req->requestvb, 
                    ASN_INTEGER, sizeof(portMode->bValue));
            if (ret != SNMP_ERR_NOERROR)
            {
                netsnmp_set_request_error(reqinfo, req, ret);
                return SNMP_ERR_NOERROR;
            }
            
            ret = netsnmp_check_vb_int_range(req->requestvb, 0, 1);
            if (ret != SNMP_ERR_NOERROR)
            {
                netsnmp_set_request_error(reqinfo, req, ret);
                return SNMP_ERR_NOERROR;
            }
            
        }
        break;

    case MODE_SET_RESERVE2:
        /* set value to backend with no commit */
        for (req = requests; req != NULL; req = req->next)
        {
            if ((portMode = netsnmp_tdata_extract_entry(req)) == NULL)
            {
                netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHINSTANCE);
                continue;
            }
            
            portMode->bValue = *req->requestvb->val.integer;

            if (SetPortMode(portMode))
            {
                netsnmp_set_request_error(reqinfo, req, SNMP_ERR_GENERR);
                return SNMP_ERR_GENERR;
            }

            req->processed = 1;
        }
 
        break;

    case MODE_SET_ACTION:
        /* commit */
        if (!CommitPortMode())
            return SNMP_ERR_GENERR;

        for (req = requests; req != NULL; req = req->next)
            req->processed = 1;

        break;

    case MODE_SET_FREE:
        if (!RollbackPortMode())
            return SNMP_ERR_GENERR;
        break;

    case MODE_SET_COMMIT:
    case MODE_SET_UNDO:
        /* nothing */
        break;

    default:
        netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
        return SNMP_ERR_GENERR;
    }
    
    return SNMP_ERR_NOERROR;
}

static int LoadPortModeTable(netsnmp_tdata *table)
{
    int i;
    netsnmp_tdata_row *row;
    struct PortMode *portMode;
    errno_t rc =-1; 
    if (!table)
        return FALSE;

    for (i = 0; i < NUM_ETHPORTS; i++)
    {
        if ((portMode = AnscAllocateMemory(sizeof(struct PortMode))) == NULL)
            goto errout;

       rc =  memset_s(portMode,sizeof(struct PortMode), 0, sizeof(struct PortMode));
       ERR_CHK(rc );

        portMode->CleanMibValueQueueFunctionPtr = NULL;

        portMode->ins = i + 1;

        if ((row = netsnmp_tdata_create_row()) == NULL)
        {
            AnscFreeMemory(portMode);
            goto errout;
        }

        row->data = portMode;
        netsnmp_tdata_row_add_index(row, ASN_UNSIGNED, &portMode->ins, sizeof(portMode->ins));
        netsnmp_tdata_add_row(table, row);
    }

    return TRUE;

errout:
    CleanupTableRow(table);
    return FALSE;
}

int
PortMode_RefreshCache(netsnmp_tdata *table)
{
    if (!FindPortModeDestComp())
        return -1;

    if (!LoadPortModeTable(table))
        return -1;

    return 0;
}
