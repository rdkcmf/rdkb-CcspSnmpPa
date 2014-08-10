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

        Implementation of functions in object "CCSP_SCALAR_HELPER_OBJECT"

		*   CcspScalarHelperRegisterMibHandler
        *   CcspScalarHelperLoadMibs

  ------------------------------------------------------------------------------

    revision:

        05/02/2012    initial revision.

**********************************************************************************/
#include "ansc_platform.h"
#include "ccsp_mib_helper.h"
#include "ccsp_scalar_helper.h"
#include "ccsp_scalar_helper_internal.h"
#include "ccsp_mib_utilities.h"

#include "ansc_load_library.h"
#include "ansc_xml_dom_parser_interface.h"
#include "ansc_xml_dom_parser_external_api.h"
#include "ansc_xml_dom_parser_status.h"

/**********************************************************************

    prototype:

		BOOL
		CcspScalarHelperLoadMibs
			(
				ANSC_HANDLE                 hThisObject,
				void*						hXmlHandle,
				void*						hLibHandle
			);

    description:

        This function is called to remove the memory of object "CCSP_SCALAR_HELPER_OBJECT".

    argument:   ANSC_HANDLE				    hThisObject
	            The handle of the object;

				void*						hXmlHandle,
				The XML handle;

				void*						hLibHandle
				The library handle if have;

	return:     None

**********************************************************************/
BOOL
CcspScalarHelperLoadMibs
	(
		ANSC_HANDLE                 hThisObject,
		void*						hXmlHandle,
		void*						hLibHandle
	)
{
	PCCSP_SCALAR_HELPER_OBJECT      pThisObject        = (PCCSP_SCALAR_HELPER_OBJECT)hThisObject;
    PANSC_XML_DOM_NODE_OBJECT       pRootNode          = (PANSC_XML_DOM_NODE_OBJECT)hXmlHandle;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode         = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode2        = (PANSC_XML_DOM_NODE_OBJECT)NULL;
	PCCSP_MIB_MAPPING				pMibMapping        = (PCCSP_MIB_MAPPING)NULL;
	BOOL							bEnabled           = TRUE;
	char							buffer[256]        = { 0 };
	ULONG							uSize              = 256;
	ULONG							uLastOid           = 0;

	/* check the name */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Scalar_name);

	if(pChildNode == NULL || ANSC_STATUS_SUCCESS != pChildNode->GetDataString(pChildNode, NULL, buffer, &uSize))
	{
		AnscTraceWarning(("Scalar group name is not configured. Failed to load.\n"));
	}

	/* copy the name */
	AnscCopyString(pThisObject->MibName, buffer);

	/* check whether it's enabled or not */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Scalar_enabled);

	if(pChildNode != NULL)
	{
		pChildNode->GetDataBoolean(pChildNode, NULL, &bEnabled);
	}

	if( !bEnabled)
	{
		AnscTraceWarning(("Scalar group '%s' is not enabled,ignore this group.\n", pThisObject->MibName));

		return TRUE;
	}

	/* check baseOid  */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Scalar_baseOid);

	uSize = 255;
	AnscZeroMemory(buffer, 256);

	if(pChildNode == NULL || ANSC_STATUS_SUCCESS != pChildNode->GetDataString(pChildNode, NULL, buffer, &uSize))
	{
		AnscTraceWarning(("baseOid is not configured in Scalar group '%s', failed to load this group.\n", pThisObject->MibName));

		return FALSE;
	}

	pThisObject->uOidLen = MAXI_CCSP_OID_LENGTH;

	if(!CcspUtilParseOidValueString(buffer, pThisObject->BaseOid, &pThisObject->uOidLen))
	{
		AnscTraceWarning(("Failed to parse baseOid value '%s' in Scalar group '%s', failed to load this group.\n", buffer, pThisObject->MibName));

		return FALSE;
	}

	/* check cacheTimeout  */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Scalar_cacheTimeout);

	if(pChildNode != NULL)
	{
		pChildNode->GetDataUlong(pChildNode, NULL, &pThisObject->uCacheTimeout);
	}

	/* check filter  */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Scalar_mapToEntry);

	uSize = 255;
	AnscZeroMemory(buffer, 256);

	if(pChildNode != NULL && ANSC_STATUS_SUCCESS == pChildNode->GetDataString(pChildNode, NULL, buffer, &uSize))
	{
		pThisObject->pMibFilter = AnscCloneString(buffer);
	}

	/* check the callbacks */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Scalar_callbacks);

	uSize = 255;
	AnscZeroMemory(buffer, 256);
	if( pChildNode != NULL)
	{
		pChildNode2 = (PANSC_XML_DOM_NODE_OBJECT)pChildNode->GetChildByName(pChildNode, CCSP_XML_Scalar_handleRequests);

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
			}
		}
	}


	/* Load MIB object one by one */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_Scalar_mapping);

	while(pChildNode != NULL)
	{
		pMibMapping = (PCCSP_MIB_MAPPING)CcspUtilLoadMibMappingInfo(pChildNode);

		if( pMibMapping != NULL)
		{
			/* add it to the queue */
			AnscQueuePushEntry(&pThisObject->MibObjQueue, &pMibMapping->Linkage);

			if(pThisObject->pMibFilter == NULL && pMibMapping->bHasMapping && AnscSizeOfString(pMibMapping->Mapping.pDMName) > 0 )
			{
				/* copy one of the mapping DM name to find corresponding CCSP Component name */
				pThisObject->pMibFilter = AnscCloneString(pMibMapping->Mapping.pDMName);
			}

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
		}

		/* get the next one */
		pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetNextChild(pRootNode, pChildNode);
	}

	/* init the value array */
	CcspUtilInitMibValueArray(&pThisObject->MibObjQueue, &pThisObject->MibValueQueue);

	/* register the MIB handler */
	pThisObject->RegisterMibHandler(pThisObject);

    return TRUE;
}

/**********************************************************************

    prototype:

		void
		CcspScalarHelperRegisterMibHandler
			(
				ANSC_HANDLE                 hThisObject
			);

    description:

        This function is called to register this scalar group mibs into NET-SNMP agent.

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

	return:     None

**********************************************************************/
int
handleScalarGroupRequest
	(
		netsnmp_mib_handler				*handler,
        netsnmp_handler_registration	*reginfo,
        netsnmp_agent_request_info		*reqinfo,
        netsnmp_request_info			*requests
	)
{
	PCCSP_SCALAR_HELPER_OBJECT      pThisObject        = (PCCSP_SCALAR_HELPER_OBJECT)reginfo->my_reg_void;
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
scalarGroupCacheLoad(netsnmp_cache * cache, void *magic)
{
	PCCSP_SCALAR_HELPER_OBJECT      pThisObject        = (PCCSP_SCALAR_HELPER_OBJECT)magic;

	return pThisObject->RefreshCache(magic);
}

void
scalarGroupCacheFree(netsnmp_cache * cache, void *magic)
{
	PCCSP_SCALAR_HELPER_OBJECT      pThisObject        = (PCCSP_SCALAR_HELPER_OBJECT)magic;

	pThisObject->ClearCache(magic);
}

void
CcspScalarHelperRegisterMibHandler
    (
        ANSC_HANDLE                 hThisObject
    )
{
	PCCSP_SCALAR_HELPER_OBJECT      pThisObject        = (PCCSP_SCALAR_HELPER_OBJECT)hThisObject;
	netsnmp_handler_registration*   reginfo_stats      = NULL;
    netsnmp_mib_handler*			mibHandler  	   = NULL;
    netsnmp_cache*                  cache			   = NULL;
    int                             oidIndex           = 0;
    oid                             oidReg[MAXI_CCSP_OID_LENGTH] = {0};

	if( pThisObject->uMinOid == 0 || pThisObject->uMaxOid == 0)
	{
		AnscTraceWarning(("The scalar group '%s' is not well-configured, drop them.\n", pThisObject->MibName));

		return;
	}

	/* register MIB handler */
	AnscTraceWarning(("Register scalar mib group '%s'\n", pThisObject->MibName));
	CcspUtilTraceOid(pThisObject->BaseOid, pThisObject->uOidLen);
    memcpy(oidReg, pThisObject->BaseOid, pThisObject->uOidLen * sizeof(oid));
    
    PSINGLE_LINK_ENTRY entry; 
    PCCSP_MIB_VALUE scalar;

    /* create common cache */
    mibHandler = netsnmp_cache_handler_get(NULL);
    if (mibHandler) 
    {
        cache = netsnmp_cache_create
    	(
         pThisObject->uCacheTimeout,
    	 scalarGroupCacheLoad,
    	 scalarGroupCacheFree,
    	 pThisObject->BaseOid,
    	 pThisObject->uOidLen
    	);
        cache->magic       = (void*)hThisObject;
        mibHandler->myvoid = (void*)cache;
        netsnmp_cache_handler_owns_cache(mibHandler);
    }

    for (entry = AnscQueueGetFirstEntry(&pThisObject->MibValueQueue); entry; entry = AnscQueueGetNextEntry(entry)){
        scalar = ACCESS_CCSP_MIB_VALUE(entry);
        oidReg[pThisObject->uOidLen] = scalar->uLastOid;

        if( !pThisObject->bHasWritable)
        {
            reginfo_stats =
                netsnmp_create_handler_registration
                (
                 pThisObject->MibName,
                 handleScalarGroupRequest,
                 oidReg,
                 pThisObject->uOidLen + 1,
                 HANDLER_CAN_RONLY
                );
        }
        else
        {
            reginfo_stats =
                netsnmp_create_handler_registration
                (
                 pThisObject->MibName,
                 handleScalarGroupRequest,
                 oidReg,
                 pThisObject->uOidLen + 1,
                 HANDLER_CAN_RWRITE
                );
        }

	    reginfo_stats->my_reg_void = (void*)hThisObject;
	    netsnmp_register_scalar(reginfo_stats);
        //netsnmp_register_scalar_group(reginfo_stats, pThisObject->uMinOid, pThisObject->uMaxOid);

        AnscTraceInfo(("  MinOid = %lu, MaxOid = %lu\n", pThisObject->uMinOid, pThisObject->uMaxOid));

        netsnmp_inject_handler
                (
                 reginfo_stats,
                 mibHandler
                );

        AnscTraceInfo(("Register Cache handler successfully.\n"));
        
    }
}

