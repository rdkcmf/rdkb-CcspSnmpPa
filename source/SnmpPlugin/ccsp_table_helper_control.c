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

/*********************************************************************************

    description:

        Implementation of functions in object "CCSP_TABLE_HELPER_OBJECT"

		*   CcspTableHelperRegisterMibHandler
        *   CcspTableHelperLoadMibs

  ------------------------------------------------------------------------------

    revision:

        05/09/2012    initial revision.

**********************************************************************************/
#include "ansc_platform.h"
#include "ccsp_mib_helper.h"
#include "ccsp_table_helper.h"
#include "ccsp_table_helper_internal.h"
#include "ccsp_mib_utilities.h"

#include "ansc_load_library.h"
#include "ansc_xml_dom_parser_interface.h"
#include "ansc_xml_dom_parser_external_api.h"
#include "ansc_xml_dom_parser_status.h"
#include "safec_lib_common.h"
/**********************************************************************

    prototype:

		BOOL
		CcspTableHelperLoadMibs
			(
				ANSC_HANDLE                 hThisObject,
				void*						hXmlHandle,
				void*						hLibHandle
			);

    description:

        This function is called to remove the memory of object "CCSP_TABLE_HELPER_OBJECT".

    argument:   ANSC_HANDLE				    hThisObject
	            The handle of the object;

				void*						hXmlHandle,
				The XML handle;

				void*						hLibHandle
				The library handle if have;

	return:     None

**********************************************************************/
BOOL
CcspTableHelperLoadMibs
	(
		ANSC_HANDLE                 hThisObject,
		void*						hXmlHandle,
		void*						hLibHandle
	)
{
	PCCSP_TABLE_HELPER_OBJECT      pThisObject         = (PCCSP_TABLE_HELPER_OBJECT)hThisObject;
    PANSC_XML_DOM_NODE_OBJECT       pRootNode          = (PANSC_XML_DOM_NODE_OBJECT)hXmlHandle;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode         = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode2        = (PANSC_XML_DOM_NODE_OBJECT)NULL;
	PCCSP_MIB_MAPPING				pMibMapping        = (PCCSP_MIB_MAPPING)NULL;
	PCCSP_INDEX_MAPPING				pIndexMapping      = (PCCSP_INDEX_MAPPING)NULL;
	BOOL							bEnabled           = TRUE;
	char							buffer[256]        = { 0 };
	ULONG							uSize              = 256;
	ULONG							uLastOid           = 0;
        errno_t rc = -1;
        int ind = -1;

	/* check the name */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Table_name);

	if(pChildNode == NULL || ANSC_STATUS_SUCCESS != pChildNode->GetDataString(pChildNode, NULL, buffer, &uSize))
	{
		AnscTraceWarning(("Table group name is not configured. Failed to load.\n"));
	}

	/* copy the name */
	rc =  strcpy_s(pThisObject->MibName,sizeof(pThisObject->MibName), buffer);
        if(rc != EOK)
        {
             ERR_CHK(rc);
             return FALSE;
         }

	/* check whether it's enabled or not */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Table_enabled);

	if(pChildNode != NULL)
	{
		pChildNode->GetDataBoolean(pChildNode, NULL, &bEnabled);
	}

	if( !bEnabled)
	{
		AnscTraceWarning(("Table group '%s' is not enabled,ignore this group.\n", pThisObject->MibName));

		return TRUE;
	}

	/* check baseOid  */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Table_tableOid);

	uSize = 255;
	AnscZeroMemory(buffer, 256);

	if(pChildNode == NULL || ANSC_STATUS_SUCCESS != pChildNode->GetDataString(pChildNode, NULL, buffer, &uSize))
	{
		AnscTraceWarning(("baseOid is not configured in Table group '%s', failed to load this group.\n", pThisObject->MibName));

		return FALSE;
	}

	pThisObject->uOidLen = MAXI_CCSP_OID_LENGTH;

	if(!CcspUtilParseOidValueString(buffer, pThisObject->BaseOid, &pThisObject->uOidLen))
	{
		AnscTraceWarning(("Failed to parse baseOid value '%s' in Table group '%s', failed to load this group.\n", buffer, pThisObject->MibName));

		return FALSE;
	}

	/* check cacheTimeout  */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Table_cacheTimeout);

	if(pChildNode != NULL)
	{
		pChildNode->GetDataUlong(pChildNode, NULL, &pThisObject->uCacheTimeout);
	}

    /* 
     * check cacheSkip
     * cacheSkip can be set to true to skip generic cache handler in framework
     * Should be used along with custom cache handler
     * By default, it's false. 
     */
    pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Table_cacheSkip);
    if(pChildNode != NULL)
    {
        pChildNode->GetDataBoolean(pChildNode, NULL, &pThisObject->bCacheSkip);
    }
    else
    {
        pThisObject->bCacheSkip = FALSE;
    }

	/* check the callbacks */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Table_callbacks);

	if( pChildNode != NULL)
	{
        /* handleRequests */
		pChildNode2 = (PANSC_XML_DOM_NODE_OBJECT)pChildNode->GetChildByName(pChildNode, CCSP_XML_Table_handleRequests);

        uSize = 255;
        AnscZeroMemory(buffer, 256);
		if( pChildNode2 != NULL && ANSC_STATUS_SUCCESS == pChildNode2->GetDataString(pChildNode2, NULL, buffer, &uSize))
		{
			if( hLibHandle == NULL)
			{
				AnscTraceWarning(("Library is NULL, failed to load callback function '%s'\n", buffer));
			}
			else
			{
				pThisObject->HandleRequestsCallback = (void*)
					 AnscGetProcAddress((ANSC_HANDLE)hLibHandle, buffer);                    				

                if (pThisObject->HandleRequestsCallback == NULL)
                {
                    AnscTraceWarning(("failed to load callback function '%s'\n", buffer));
                }
			}
		}

        /* refreshCache */
		pChildNode2 = (PANSC_XML_DOM_NODE_OBJECT)pChildNode->GetChildByName(pChildNode, CCSP_XML_Table_refreshCache);

        uSize = 255;
        AnscZeroMemory(buffer, 256);
		if( pChildNode2 != NULL && ANSC_STATUS_SUCCESS == pChildNode2->GetDataString(pChildNode2, NULL, buffer, &uSize))
		{
			if( hLibHandle == NULL)
			{
				AnscTraceWarning(("Library is NULL, failed to load callback function '%s'\n", buffer));
			}
			else
			{
				pThisObject->RefreshCacheCallback = (void*)
					 AnscGetProcAddress((ANSC_HANDLE)hLibHandle, buffer);                    				

                if (pThisObject->RefreshCacheCallback == NULL)
                {
                    AnscTraceWarning(("failed to load callback function '%s'\n", buffer));
                }
			}
		}
	}

	/* Load index from now on */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Table_index);

	while(pChildNode != NULL)
	{
		rc = strcmp_s(CCSP_XML_Table_index,strlen(CCSP_XML_Table_index),pChildNode->GetName(pChildNode), &ind);
                ERR_CHK(rc);
                if((ind) && (rc == EOK))
		{
			break;
		}

		pIndexMapping = (PCCSP_INDEX_MAPPING)CcspUtilLoadIndexMapping(pChildNode);

		if( pIndexMapping != NULL)
		{
			/* add it to the queue */
			AnscQueuePushEntry(&pThisObject->IndexMapQueue, &pIndexMapping->Linkage);
		}

		/* get the next one */
		pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetNextChild(pRootNode, pChildNode);
	}

	/* Load MIB object one by one */
	while(pChildNode != NULL)
	{
		rc = strcmp_s(CCSP_XML_Table_mapping, strlen(CCSP_XML_Table_mapping),pChildNode->GetName(pChildNode), &ind);
                ERR_CHK(rc);
                if((ind) && (rc == EOK))
		{
			break;
		}

		pMibMapping = (PCCSP_MIB_MAPPING)CcspUtilLoadMibMappingInfo(pChildNode);

		if( pMibMapping != NULL)
		{
			/* add it to the queue */
			AnscQueuePushEntry(&pThisObject->MibObjQueue, &pMibMapping->Linkage);

			/* recalculate the min and max oid */
			uLastOid = pMibMapping->MibInfo.uLastOid;
			if( pThisObject->uMinOid == 0 || pThisObject->uMinOid > uLastOid)
			{
				pThisObject->uMinOid = uLastOid;
			}

			if( pThisObject->uMaxOid < uLastOid )
			{
				pThisObject->uMaxOid = uLastOid;
			}
			
			/* mark bHasWritable if have */
			if( pMibMapping->MibInfo.bWritable)
			{
				pThisObject->bHasWritable = TRUE;
			}

			/* check whether has rowstatus or not */
			if( pMibMapping->MibInfo.bIsRowStatus)
			{
				pThisObject->uRowStatus = pMibMapping->MibInfo.uLastOid;
			}

			if( AnscSizeOfString(pThisObject->pStrSampleDM) == 0 && pMibMapping->bHasMapping)
			{
				rc = strcpy_s(pThisObject->pStrSampleDM,sizeof(pThisObject->pStrSampleDM), pMibMapping->Mapping.pDMName);
                                 if(rc != EOK)
                                 {
                                    ERR_CHK(rc);
                                    return FALSE;
                                  }
			}
		}

		/* get the next one */
		pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetNextChild(pRootNode, pChildNode);
	}

	/* register the MIB handler */
	pThisObject->RegisterMibHandler(pThisObject);

    return TRUE;
}

/**********************************************************************

    prototype:

		void
		CcspTableHelperRegisterMibHandler
			(
				ANSC_HANDLE                 hThisObject
			);

    description:

        This function is called to register this table group mibs into NET-SNMP agent.

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

	return:     None

**********************************************************************/
int
ccspAddTableIndexes
(
    ANSC_HANDLE						  hThisObject,
    netsnmp_table_registration_info*  table_info
)
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject					= (PCCSP_TABLE_HELPER_OBJECT)hThisObject;
	ULONG							index[MAXI_MIB_INDEX_COUNT] = { 0 };
	PCCSP_INDEX_MAPPING				pIndexMap                   = (PCCSP_INDEX_MAPPING)NULL;
	ULONG							indexCount                  = 0;
    PSINGLE_LINK_ENTRY              pSLinkEntry					= (PSINGLE_LINK_ENTRY)NULL;

	pSLinkEntry = AnscQueueGetFirstEntry(&pThisObject->IndexMapQueue);

    while ( pSLinkEntry && indexCount < MAXI_MIB_INDEX_COUNT )
    {
        pIndexMap       = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);
        pSLinkEntry     = AnscQueueGetNextEntry(pSLinkEntry);

		if( pIndexMap != NULL)
		{
			index[indexCount] = pIndexMap->MibInfo.uType;
			indexCount ++;
		}
    }

	if( indexCount == 0)
	{
		AnscTraceError(("No index is defined in table '%s', something is wrong.\n", pThisObject->MibName));

		return -1;
	}

	if( indexCount == 1)
	{
		netsnmp_table_helper_add_indexes(table_info, (u_char)index[0],0);
	}
	else if( indexCount == 2)
	{
		netsnmp_table_helper_add_indexes(table_info, (u_char)index[0],(u_char)index[1],0);
	}
	else if( indexCount == 3)
	{
		netsnmp_table_helper_add_indexes(table_info, (u_char)index[0],(u_char)index[1],(u_char)index[2],0);
	}
	else if( indexCount == 4)
	{
		netsnmp_table_helper_add_indexes(table_info, (u_char)index[0],(u_char)index[1],(u_char)index[2],(u_char)index[3],0);
	}
	else if( indexCount == 5)
	{
		netsnmp_table_helper_add_indexes(table_info, (u_char)index[0],(u_char)index[1],(u_char)index[2],(u_char)index[3],(u_char)index[4],0);
	}
	else if( indexCount == 6)
	{
		netsnmp_table_helper_add_indexes(table_info, (u_char)index[0],(u_char)index[1],(u_char)index[2],(u_char)index[3],(u_char)index[4],(u_char)index[5],0);
	}
	else
	{
		AnscTraceError(("Too many indexes (%lu) to handle, ignore them.\n", indexCount));

		return -1;
	}

	return 0;
}

int
handleTableGroupRequest
	(
		netsnmp_mib_handler				*handler,
        netsnmp_handler_registration	*reginfo,
        netsnmp_agent_request_info		*reqinfo,
        netsnmp_request_info			*requests
	)
{
	PCCSP_TABLE_HELPER_OBJECT      pThisObject        = (PCCSP_TABLE_HELPER_OBJECT)reginfo->my_reg_void;
	Netsnmp_Node_Handler*			pHandler           = NULL;

	if( pThisObject == NULL)
	{
		return 0;
	}

	/* call the callback if have */
	if( pThisObject->HandleRequestsCallback != NULL)
	{
		pHandler = (Netsnmp_Node_Handler*)pThisObject->HandleRequestsCallback;

		pHandler(handler,reginfo, reqinfo, requests);
	}

	/* check the request types */
	if (reqinfo->mode >= MODE_SET_RESERVE1 && reqinfo->mode <= MODE_SET_UNDO)		
	{
		if(!pThisObject->bHasWritable)
		{
			netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
			return SNMP_ERR_GENERR;
		}
		else
		{
			return pThisObject->SetMibValues(pThisObject, reqinfo, requests);
		}
	}
	else if( MODE_GET == reqinfo->mode) 
	{
		return pThisObject->GetMibValues(pThisObject, reqinfo, requests);
	}

	return SNMP_ERR_NOERROR;
}


int
tableGroupCacheLoad(netsnmp_cache * cache, void *magic)
{
	UNREFERENCED_PARAMETER(cache);
	PCCSP_MIB_TABLE_MAGIC      pMagic             = (PCCSP_MIB_TABLE_MAGIC)magic;
	PCCSP_TABLE_HELPER_OBJECT  pThisObject        = (PCCSP_TABLE_HELPER_OBJECT)pMagic->pMibHandler;

	AnscTraceInfo(("Enter 'tableGroupCacheLoad' of table '%s'\n", pThisObject->MibName));
	return pThisObject->RefreshCache((ANSC_HANDLE)pThisObject);
}

void
tableGroupCacheFree(netsnmp_cache * cache, void *magic)
{
        UNREFERENCED_PARAMETER(cache);
	PCCSP_MIB_TABLE_MAGIC      pMagic             = (PCCSP_MIB_TABLE_MAGIC)magic;
	netsnmp_tdata*			   pTable             = (netsnmp_tdata*)pMagic->pTableData;
	PCCSP_TABLE_HELPER_OBJECT  pThisObject        = (PCCSP_TABLE_HELPER_OBJECT)pMagic->pMibHandler;
    netsnmp_tdata_row*		   pRow				  = NULL;


	AnscTraceInfo(("Enter 'tableGroupCacheFree' of table '%s'\n", pThisObject->MibName));

	while ((pRow = netsnmp_tdata_row_first (pTable)))
	{
		CcspUtilRemoveMibEntry(pTable, pRow);
    }
}

void
CcspTableHelperRegisterMibHandler
    (
        ANSC_HANDLE                 hThisObject
    )
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject        = (PCCSP_TABLE_HELPER_OBJECT)hThisObject;
	netsnmp_handler_registration*   reg                = NULL;
    netsnmp_mib_handler*		    mibHandler  	   = NULL;
    netsnmp_cache*                  cache			   = NULL;
    netsnmp_tdata                   *table_data;
    netsnmp_table_registration_info *table_info;

	if( pThisObject->uMinOid == 0 || pThisObject->uMaxOid == 0)
	{
		AnscTraceWarning(("The table mib '%s' is not well-configured, drop them.\n", pThisObject->MibName));

		return;
	}

	/* register MIB handler */
	AnscTraceInfo(("Register table mib '%s'\n", pThisObject->MibName));
	CcspUtilTraceOid(pThisObject->BaseOid, pThisObject->uOidLen);

	if( !pThisObject->bHasWritable)
	{
		reg =
			netsnmp_create_handler_registration
			(
				pThisObject->MibName,
				handleTableGroupRequest,
				pThisObject->BaseOid,
				pThisObject->uOidLen,
				HANDLER_CAN_RONLY
			);
	}
	else
	{
		reg =
			netsnmp_create_handler_registration
			(
				pThisObject->MibName,
				handleTableGroupRequest,
				pThisObject->BaseOid,
				pThisObject->uOidLen,
				HANDLER_CAN_RWRITE
			);
	}

	reg->my_reg_void = (void*)hThisObject;
	AnscTraceInfo(("MinOid = %lu, MaxOid = %lu\n", pThisObject->uMinOid, pThisObject->uMaxOid));

    table_data = netsnmp_tdata_create_table( pThisObject->MibName, 0 );
    table_info = SNMP_MALLOC_TYPEDEF( netsnmp_table_registration_info );
	pThisObject->mibMagic.pTableData = (void*)table_data;

	/* add indexes */
	ccspAddTableIndexes(hThisObject, table_info);

	/* set column infor */
	table_info->min_column = pThisObject->uMinOid;
	table_info->max_column = pThisObject->uMaxOid;
    
    netsnmp_tdata_register( reg, table_data, table_info );

	/* register MIB cache */
    mibHandler = netsnmp_cache_handler_get(NULL);
    if (mibHandler) 
	{
        cache = netsnmp_cache_create
				(
			  		 pThisObject->uCacheTimeout,
					 tableGroupCacheLoad,
					 tableGroupCacheFree,
 					 pThisObject->BaseOid,
					 pThisObject->uOidLen
   			    );
 
		/* no cache refresh after set */
		cache->flags |= NETSNMP_CACHE_DONT_INVALIDATE_ON_SET;

		cache->magic       = (void*)&pThisObject->mibMagic;
        mibHandler->myvoid = (void*)cache;
        netsnmp_cache_handler_owns_cache(mibHandler);

		netsnmp_inject_handler
			(
				reg,
				mibHandler
			);

		AnscTraceInfo(("Register Cache handler for Table Mibs successfully.\n"));
	}
}

