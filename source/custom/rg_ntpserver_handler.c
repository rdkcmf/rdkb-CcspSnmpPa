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
#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "net-snmp/agent/net-snmp-agent-includes.h"

#define NUM_NTPSERV             3

#define NTPSERV_DM_OBJ          "Device.Time."
#define NTPSERV_DM_PARAM_PAT    "Device.Time.NTPServer%d"

struct NTPServer 
{
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

    if (!Cosa_FindDestComp(NTPSERV_DM_OBJ, &dstComp, &dstPath)
            || !dstComp || !dstPath)
    {
        AnscTraceError(("%s: fail to find dest comp\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

static BOOL GetNtpServer(struct NTPServer *ntpServ)
{
    parameterValStruct_t **valStr;
    int nval;
    char *name[1];

    name[0] = ntpServ->dmName;
    if (!Cosa_GetParamValues(dstComp, dstPath, name, 1, &nval, &valStr))
    {
        AnscTraceError(("%s: fail to get: %s\n", __FUNCTION__, ntpServ->dmName));
        return FALSE;
    }

    if (nval < 1)
    {
        AnscTraceError(("%s: nval < 1 \n", __FUNCTION__));
        return FALSE;
    }

    snprintf(ntpServ->server, sizeof(ntpServ->server), "%s", valStr[0]->parameterValue);
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
        AnscTraceError(("%s: fail to set: %s\n", __FUNCTION__, ntpServ->dmName));
        return FALSE;
    }

    return TRUE;
}

static BOOL CommitNtpServer(void)
{
    if (!Cosa_SetCommit(dstComp, dstPath, TRUE))
    {
        AnscTraceError(("%s: fail to commit\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

static BOOL RollbackNtpServer(void)
{
    if (!Cosa_SetCommit(dstComp, dstPath, FALSE))
    {
        AnscTraceError(("%s: fail to rollback\n", __FUNCTION__));
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
    
    if (!table)
        return FALSE;

    for (i = 0; i < NUM_NTPSERV; i++)
    {
        if ((ntpServ = AnscAllocateMemory(sizeof(struct NTPServer))) == NULL)
            goto errout;

        memset(ntpServ, 0, sizeof(struct NTPServer));
        ntpServ->ins = i + 1;
        snprintf(ntpServ->dmName, sizeof(ntpServ->dmName), NTPSERV_DM_PARAM_PAT, ntpServ->ins);

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
    netsnmp_request_info        *req;
    struct NTPServer            *ntpServ;
    int                         ret, ncp;

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
            memset(ntpServ->server, 0, sizeof(ntpServ->server));
            ncp = req->requestvb->val_len > sizeof(ntpServ->server) - 1 ?
                sizeof(ntpServ->server) - 1 : req->requestvb->val_len;
            strncpy(ntpServ->server, (char *)req->requestvb->val.string, ncp);

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
