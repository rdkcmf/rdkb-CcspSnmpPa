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

        Implementation of functions in object "CCSP_SCALAR_HELPER_OBJECT"

		*   CcspScalarHelperSetMibValues
		*   CcspScalarHelperGetMibValues
		*   CcspScalarHelperRefreshCache
		*   CcspScalarHelperClearCache

  ------------------------------------------------------------------------------

    revision:

        05/03/2012    initial revision.

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

#include "cosa_api.h"

#include<time.h>
#include "safec_lib_common.h"

/**********************************************************************

    prototype:

		int
		CcspScalarHelperGetMibValues
			(
				ANSC_HANDLE                 hThisObject,
				netsnmp_agent_request_info  *reqinfo,
				netsnmp_request_info		*requests
			);

    description:

        This function is called to retrieve MIB values.

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

				netsnmp_agent_request_info  *reqinfo,
				The request info

				netsnmp_request_info		*requests
				The requests;

	return:     The error code

**********************************************************************/
int
CcspScalarHelperGetMibValues
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	)
{
	PCCSP_SCALAR_HELPER_OBJECT      pThisObject     = (PCCSP_SCALAR_HELPER_OBJECT)hThisObject;
	PCCSP_MIB_VALUE                 pMibValueObj    = (PCCSP_MIB_VALUE)NULL;
    netsnmp_request_info            *request		= NULL;
    netsnmp_variable_list           *requestvb		= NULL;
    oid                             subid			= 0;

    for (request = requests; request != NULL; request = request->next) 
	{
		if( request->processed != 0) { continue;}

        requestvb = request->requestvb;
		subid     = requestvb->name[pThisObject->uOidLen];
		pMibValueObj = CcspUtilLookforMibValueObjWithOid(&pThisObject->MibValueQueue, subid);

		if( pMibValueObj != NULL)
		{
			if( pMibValueObj->uType == ASN_INTEGER || pMibValueObj->uType == ASN_BOOLEAN ||
				(pMibValueObj->uType >= ASN_IPADDRESS && pMibValueObj->uType <= ASN_OPAQUE))
			{
				snmp_set_var_typed_value(request->requestvb, (u_char)pMibValueObj->uType,
					(u_char *)&pMibValueObj->Value.uValue, pMibValueObj->uSize);

			}
			else if( pMibValueObj->uType == ASN_BIT_STR || pMibValueObj->uType == ASN_OCTET_STR)
			{
				snmp_set_var_typed_value(request->requestvb, (u_char)pMibValueObj->uType,
					(u_char *)pMibValueObj->Value.pBuffer, pMibValueObj->uSize);
			}
			else if( pMibValueObj->uType == ASN_COUNTER64)
			{
				snmp_set_var_typed_value(request->requestvb, (u_char)pMibValueObj->uType,
					(u_char *)&pMibValueObj->Value.u64Value, pMibValueObj->uSize);
			}
			else
			{
				AnscTraceWarning(("Unknown MIB type '%lu'\n", pMibValueObj->uType));
			}
		}

		else
		{
			netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
		}
	}

    return SNMP_ERR_NOERROR;
}

/**********************************************************************

		int
		CcspScalarHelperSetMibValues
			(
				ANSC_HANDLE                 hThisObject,
				netsnmp_agent_request_info  *reqinfo,
				netsnmp_request_info		*requests
			);

    description:

        This function is called to set MIB values.

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

				netsnmp_agent_request_info  *reqinfo,
				The request info

				netsnmp_request_info		*requests
				The requests;

	return:     The error code

**********************************************************************/
static 
int
verifyTypeAndValueInSetReserved1
	(
		netsnmp_variable_list*				pVb,
		PCCSP_MIB_MAPPING					pMapping
	)
{
	int								ret              = SNMP_ERR_NOERROR;
	ULONG							nType            = pMapping->MibInfo.uType;

	if(!pMapping->MibInfo.bWritable)
	{
		return SNMP_ERR_NOTWRITABLE;
	}

	/* check type first */
	ret = netsnmp_check_vb_type(pVb, nType);

	if( ret != SNMP_ERR_NOERROR)
	{
		return ret;
	}

	if( nType == ASN_BOOLEAN)
	{
		ret = netsnmp_check_vb_size(pVb, sizeof(BOOLEAN));
	}
	else if( nType == ASN_INTEGER || (nType >= ASN_IPADDRESS && nType <= ASN_OPAQUE))
	{
		ret = netsnmp_check_vb_size(pVb, sizeof(ULONG));
	}
	else if( nType == ASN_COUNTER64)
	{
		ret = netsnmp_check_vb_size(pVb, sizeof(U64));
	}

	if( ret != SNMP_ERR_NOERROR)
	{
		return ret;
	}

	if( pMapping->MibInfo.uMaskLimit == CCSP_MIB_LIMIT_MAX)
	{
		if( pMapping->MibInfo.uType == ASN_OCTET_STR)
		{
			ret = netsnmp_check_vb_max_size(pVb, pMapping->MibInfo.nMax);
		}			
	}
	else if( pMapping->MibInfo.uMaskLimit == CCSP_MIB_LIMIT_BOTH)
	{
		if( pMapping->MibInfo.uType == ASN_INTEGER )
		{
			ret = netsnmp_check_vb_int_range(pVb, pMapping->MibInfo.nMin, pMapping->MibInfo.nMax);
		}
		else if ( pMapping->MibInfo.uType == ASN_UNSIGNED )
		{
			ret = netsnmp_check_vb_range(pVb, pMapping->MibInfo.nMin, pMapping->MibInfo.nMax);
		}
		else if( pMapping->MibInfo.uType == ASN_OCTET_STR)
		{
			ret = netsnmp_check_vb_size_range(pVb, pMapping->MibInfo.nMin, pMapping->MibInfo.nMax);
		}
	}

	if( ret != SNMP_ERR_NOERROR)
	{
		return ret;
	}

	/* check mapping if have */
	if( nType == ASN_INTEGER || nType == ASN_UNSIGNED)
	{
		if( pMapping->MapQueue.Depth > 0)
		{
			if( CcspUtilLookforEnumMapping(&pMapping->MapQueue, (ULONG)*pVb->val.integer) == NULL)
			{
				AnscTraceError(("Invalid integer value '%ld'\n", *pVb->val.integer));

				ret = SNMP_ERR_WRONGVALUE;
			}
		}
	}
	return ret;
}

static
int
scalarGroupSetReserve2
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	)
{
        UNREFERENCED_PARAMETER(reqinfo);
	PCCSP_SCALAR_HELPER_OBJECT      pThisObject     = (PCCSP_SCALAR_HELPER_OBJECT)hThisObject;
    netsnmp_request_info            *request		= NULL;
    netsnmp_variable_list           *requestvb		= NULL;
	PCCSP_MIB_MAPPING				pMapping        = NULL;
    oid                             subid			= 0;
	int								i               = 0;
	ULONG							uCount          = 0;
	parameterValStruct_t*			pValueArray	    = NULL;
	BOOL							bResult         = FALSE;
	/* first round check how many parameters will be set */
	for (request = requests; request != NULL; request = request->next) 
	{
		if( request->processed != 0) { continue;}

		requestvb = request->requestvb;
		subid     = requestvb->name[pThisObject->uOidLen];
		pMapping  = CcspUtilLookforMibMapWithOid(&pThisObject->MibObjQueue, subid);

		if( pMapping && pMapping->bHasMapping)
		{
			uCount ++;
		}
	}

	if( uCount == 0)
	{
		/* the mibs maybe be handled by callback apis. We return success here. */
		return SNMP_ERR_NOERROR;
	}

	/* allocate memory and get ready to set */
	pValueArray = (parameterValStruct_t*)AnscAllocateMemory(sizeof(parameterValStruct_t) * uCount);

	if( pValueArray == NULL)
	{
		return SNMP_ERR_GENERR;
	}

	/* Second round to transfer mib value to DM value */
	uCount = 0;
	for (request = requests; request != NULL; request = request->next) 
	{
		if( request->processed != 0) { continue;}

		requestvb = request->requestvb;
		subid     = requestvb->name[pThisObject->uOidLen];
		pMapping  = CcspUtilLookforMibMapWithOid(&pThisObject->MibObjQueue, subid);

		if( pMapping && pMapping->bHasMapping)
		{
			pValueArray[uCount].parameterName = AnscCloneString(pMapping->Mapping.pDMName);
			pValueArray[uCount].type          = (enum dataType_e)pMapping->Mapping.uDataType;

#if 0
   			/* don't need to do it, the cache will be refreshed anyway */
			if( pMibValueObj != NULL)
			{
				if( pMapping->MibInfo.uType == ASN_OCTET_STR)
				{
					pMibValueObj->BackValue.pBuffer = pMibValueObj->Value.pBuffer;
					pMibValueObj->uBackSize         = pMibValueObj->uSize;

					pMibValueObj->Value.pBuffer     = AnscCloneString((char*)requestvb->val.string);
					pMibValueObj->uSize             = requestvb->val_len;
				}
				else
				{
					pMibValueObj->BackValue.uValue  = pMibValueObj->Value.uValue;
					pMibValueObj->uBackSize         = pMibValueObj->uSize;

					pMibValueObj->Value.uValue     = *requestvb->val.integer;
					pMibValueObj->uSize             = requestvb->val_len;
				}
			}
#endif
			/* parse MIB value to DM value */
			CcspUtilMIBValueToDM(pMapping, (void*)&pValueArray[uCount], requestvb);

			/*
		    AnscTraceFlow
		    	((
		    		"SnmpPA - scalarGroupSetReserve2, ucount = %d, name = %s, type = %d, value = %s, MIB type = %d, length = %d, value = %02X%02X%02X%02X%02X%02X.\n",
		    		uCount,
		    		pValueArray[uCount].parameterName,
		    		pValueArray[uCount].type,
		    		pValueArray[uCount].parameterValue,
		    		requestvb->type,
		    		requestvb->val_len,
		    		(requestvb->val_len > 0) ? requestvb->val.string[0] : 0xFF,
		    		(requestvb->val_len > 1) ? requestvb->val.string[1] : 0xFF,
		    		(requestvb->val_len > 2) ? requestvb->val.string[2] : 0xFF,
		    		(requestvb->val_len > 3) ? requestvb->val.string[3] : 0xFF,
		    		(requestvb->val_len > 4) ? requestvb->val.string[4] : 0xFF,
		    		(requestvb->val_len > 5) ? requestvb->val.string[5] : 0xFF
		    	));
		     */

			pThisObject->bBackground |= pMapping->Mapping.backgroundCommit;
			uCount ++;
		}
	}

	/* call SetParamValue */
	bResult = 
		Cosa_SetParamValuesNoCommit
			(
				pThisObject->pCcspComp,
				pThisObject->pCcspPath,
				pValueArray,
				uCount
				);

	/* free the memory */
	if( pValueArray != NULL)
	{
		for( i = 0; i < (int)uCount; i ++)
		{
			if( pValueArray[i].parameterValue != NULL) AnscFreeMemory(pValueArray[i].parameterValue);
		}

		AnscFreeMemory(pValueArray);
	}

	if( bResult)
	{
		return SNMP_ERR_NOERROR;
	}
	else
	{
		return SNMP_ERR_GENERR;
	}
}

static
int
scalarGroupSetFree
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	)
{
        UNREFERENCED_PARAMETER(reqinfo);
        UNREFERENCED_PARAMETER(requests);
	UNREFERENCED_PARAMETER(hThisObject);
#if 0  /* don't need to do anything. The cache will be refreshed anyway */
	/* roll back the save values */
	for (request = requests; request != NULL; request = request->next) 
	{
		if( request->processed != 0) { continue;}

		requestvb = request->requestvb;
		subid     = requestvb->name[pThisObject->uOidLen];
		pMibValueObj = CcspUtilLookforMibValueObjWithOid(&pThisObject->MibValueQueue, subid);

		if( pMibValueObj != NULL)
		{
			if( pMibValueObj->uType == ASN_OCTET_STR)
			{
				if( pMibValueObj->Value.pBuffer != NULL)  AnscFreeMemory(pMibValueObj->Value.pBuffer);

				pMibValueObj->Value.pBuffer     = pMibValueObj->BackValue.pBuffer;
				pMibValueObj->uSize             = pMibValueObj->uBackSize;

				pMibValueObj->BackValue.pBuffer = NULL;
				pMibValueObj->uBackSize         = 0;
			}
			else
			{
				pMibValueObj->Value.uValue      = pMibValueObj->BackValue.uValue;
				pMibValueObj->uSize             = pMibValueObj->uBackSize;

				pMibValueObj->BackValue.uValue  = 0;
				pMibValueObj->uBackSize         = pMibValueObj->uSize;
			}
		}
	}
#endif

	return SNMP_ERR_NOERROR;
}

int
CcspScalarHelperSetMibValues
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	)
{
	PCCSP_SCALAR_HELPER_OBJECT      pThisObject     = (PCCSP_SCALAR_HELPER_OBJECT)hThisObject;
    netsnmp_request_info            *request		= NULL;
    netsnmp_variable_list           *requestvb		= NULL;
	PCCSP_MIB_MAPPING				pMapping        = NULL;
    oid                             subid			= 0;
	int								ret             = 0;

	switch( reqinfo->mode)
	{
		case MODE_SET_RESERVE1:

			for (request = requests; request != NULL; request = request->next) 
			{
				if( request->processed != 0) { continue;}

				requestvb = request->requestvb;
				subid     = requestvb->name[pThisObject->uOidLen];
				pMapping  = CcspUtilLookforMibMapWithOid(&pThisObject->MibObjQueue, subid);

				if( pMapping)
				{
					ret = verifyTypeAndValueInSetReserved1(request->requestvb, pMapping);

					if( ret != SNMP_ERR_NOERROR)
					{
						netsnmp_set_request_error(reqinfo, request, ret);

						return SNMP_ERR_NOERROR;
					}
				}
				else
				{
					netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
					return SNMP_ERR_NOERROR;
				}
			}

			break;

		case MODE_SET_RESERVE2:

			/* collect all the updated values and call Cosa_SetParamValues with Commit = FALSE */
			return scalarGroupSetReserve2(hThisObject, reqinfo, requests);

			break;

		case MODE_SET_ACTION:

			if( pThisObject->pCcspComp != NULL && pThisObject->pCcspPath)
			{
				/* commit the update */
				if (pThisObject->bBackground) 
				{
					Cosa_BackgroundCommit(pThisObject->pCcspComp, pThisObject->pCcspPath, TRUE);
					pThisObject->bBackground = 0;
                                        struct timespec delay = {0, 80000000};
                                        nanosleep(&delay, NULL);
				}
				else
				{
					Cosa_SetCommit(pThisObject->pCcspComp, pThisObject->pCcspPath, TRUE);
				}
			}
			return SNMP_ERR_NOERROR;

		case MODE_SET_FREE:

			if( pThisObject->pCcspComp != NULL && pThisObject->pCcspPath)
			{
				/* don't commit the update */
				Cosa_SetCommit(pThisObject->pCcspComp, pThisObject->pCcspPath, FALSE);
			}

			/* roll back the update */
	       return scalarGroupSetFree(hThisObject, reqinfo, requests);

		case MODE_SET_COMMIT:
		case MODE_SET_UNDO:
		default:

			/* we don't care about them */
			return SNMP_ERR_NOERROR;
	}

    return SNMP_ERR_NOERROR;
}
/**********************************************************************

    prototype:

		int
		CcspScalarHelperRefreshCache
			(
				ANSC_HANDLE                 hThisObject
			);

    description:

        One of the cache handler function to load values for cache.

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

	return:     The result of refresh cache

**********************************************************************/
int
CcspScalarHelperRefreshCache
	(
        ANSC_HANDLE                 hThisObject
	)
{
	PCCSP_SCALAR_HELPER_OBJECT      pThisObject     = (PCCSP_SCALAR_HELPER_OBJECT)hThisObject;
	char*							pDMString       = pThisObject->pMibFilter;
	char*							pDestComp       = NULL;
	char*							pDestPath       = NULL;
	PCCSP_MIB_MAPPING				pMibMap			= (PCCSP_MIB_MAPPING)NULL;
	PSINGLE_LINK_ENTRY              pSLinkEntry     = (PSINGLE_LINK_ENTRY)NULL;
	char                            pTemp[256]      = { 0 };
	ULONG							uInsNumber      = 0;
        errno_t rc = -1;
        int ind = -1;
       

	if( pDMString == NULL)
	{
		AnscTraceWarning(("No one DM param name is configured, no way to cache.\n"));

		return -1;
	}

	/* first time we need to figure out which component to talk with */
	if( !pThisObject->pCcspComp || !pThisObject->pCcspPath)
	{
		pThisObject->nCacheMibCount = 0;

		/* This is the first time, we need to get the corresponding CCSP component Info */
		if( _ansc_strstr(pDMString, "%d") != NULL || _ansc_strstr(pDMString, "=") != NULL)
		{
			/* filter mapping, will take care later */
			uInsNumber = CcspUtilDMFilterToNamespace(pDMString, &pThisObject->pCcspComp, &pThisObject->pCcspPath);
			
			if( uInsNumber == 0)
			{
				AnscTraceWarning(("Failed to find the entry who has '%s'\n", pDMString));

				return -1;
			}

			/* then add all the DM names in the CacheName array */
			pSLinkEntry = AnscQueueGetFirstEntry(&pThisObject->MibObjQueue);

			while ( pSLinkEntry )
			{
				pMibMap         = ACCESS_CCSP_MIB_MAPPING(pSLinkEntry);
				pSLinkEntry     = AnscQueueGetNextEntry(pSLinkEntry);

				if( pMibMap != NULL && pMibMap->bHasMapping)
				{
					/* add the DM name to cache array */
					if(pThisObject->nCacheMibCount < MAXI_MIB_COUNT_IN_GROUP)
					{
						if( _ansc_strstr(pMibMap->Mapping.pDMName, "%d") != NULL)
						{
						rc =	strcpy_s(pTemp,sizeof(pTemp), pMibMap->Mapping.pDMName);
                                                            if(rc != EOK)
                                                           {
                                                                ERR_CHK(rc);
                                                                 return -1;
                                                            }
							rc = sprintf_s(pMibMap->Mapping.pDMName,sizeof(pMibMap->Mapping.pDMName), pTemp, uInsNumber);
                                                        if(rc < EOK)
                                                           {
                                                                ERR_CHK(rc);
                                                                 return -1;
                                                            }

						}

						pThisObject->CacheMibOid[pThisObject->nCacheMibCount]  = pMibMap->MibInfo.uLastOid;
						pThisObject->CacheDMName[pThisObject->nCacheMibCount]  = pMibMap->Mapping.pDMName;
						pThisObject->nCacheMibCount ++;

						CcspTraceDebug(("Adding to cache: lastOid %lu, DMName %s\n", pMibMap->MibInfo.uLastOid, pMibMap->Mapping.pDMName));
					}
				}
			}
		}
		else
		{

			if( !Cosa_FindDestComp(pDMString, &pThisObject->pCcspComp, &pThisObject->pCcspPath) )
			{
				AnscTraceWarning(("Failed to find the CCSP component who supports '%s'\n", pDMString));

				return -1;
			}

			/* verify the other MIB mappings to be in the same Component */
			pSLinkEntry = AnscQueueGetFirstEntry(&pThisObject->MibObjQueue);

			while ( pSLinkEntry )
			{
				pMibMap         = ACCESS_CCSP_MIB_MAPPING(pSLinkEntry);
				pSLinkEntry     = AnscQueueGetNextEntry(pSLinkEntry);

				pDestComp       = NULL;
				pDestPath       = NULL;

				if(Cosa_FindDestComp(pMibMap->Mapping.pDMName, &pDestComp, &pDestPath))
				{
                                        rc = strcmp_s(pThisObject->pCcspComp,strlen(pThisObject->pCcspComp),pDestComp,&ind);
                                        ERR_CHK(rc);
                                        if ( (rc != EOK) ||  (!ind) )
                                        {
                                           rc = strcmp_s( pThisObject->pCcspPath,strlen(pThisObject->pCcspPath),pDestPath, &ind);
                                           ERR_CHK(rc);
                                        }

                                        if ( (rc == EOK) && (ind) )
					{
                                        	CcspTraceDebug(("Different Ccsp Component '%s' for DM namespace '%s' \n", pDestComp, pMibMap->Mapping.pDMName));
					}
					else
					{
						/* add the DM name to cache array */
						if(pThisObject->nCacheMibCount < MAXI_MIB_COUNT_IN_GROUP)
						{
							pThisObject->CacheMibOid[pThisObject->nCacheMibCount]  = pMibMap->MibInfo.uLastOid;
							pThisObject->CacheDMName[pThisObject->nCacheMibCount]  = pMibMap->Mapping.pDMName;
							pThisObject->nCacheMibCount ++;

							CcspTraceDebug(("Adding to cache: lastOid %lu, DMName %s\n", pMibMap->MibInfo.uLastOid, pMibMap->Mapping.pDMName));
						}
					}
				}
				else
				{
					AnscTraceError(("Unable to find the component to support DM namespace '%s', Error!\n", pMibMap->Mapping.pDMName));
				}

				if( pDestComp){   AnscFreeMemory(pDestComp); pDestComp = NULL;}
				if( pDestPath){   AnscFreeMemory(pDestPath); pDestPath = NULL;}
			}
		}
	}

	if( pThisObject->nCacheMibCount == 0)
	{
		AnscTraceError(("No one mib is register in the cache, just exit.\n"));

		return -1;
	}

	/* Get all the values in the cache */
	if( TRUE )
	{
		int                       size			= 0;
		parameterValStruct_t**    paramValues	= NULL;
		parameterValStruct_t*	  pValue        = NULL;
		int						  i				= 0;
		int						  j             = 0;
		PCCSP_MIB_VALUE			  pMibValue     = (PCCSP_MIB_VALUE)NULL;
		PCCSP_MIB_MAPPING	      pMapping      = (PCCSP_MIB_MAPPING)NULL;

		if( !Cosa_GetParamValues(pThisObject->pCcspComp, pThisObject->pCcspPath, pThisObject->CacheDMName, pThisObject->nCacheMibCount, &size, &paramValues))
		{
			return -1;
		}

        CcspTraceDebug(("Cosa_GetParamValues:\n"));

		/* put them in the value array */
		for( i = 0; i< size; i ++)
		{
			pValue = paramValues[i];
                  /*Coverity Fix : CID:54264 Forward NULL  */
                  if ( ( pValue->parameterName != NULL ) && (pValue->parameterValue != NULL) )
                  {
                      CcspTraceDebug(("  %s %s\n", pValue->parameterName, pValue->parameterValue));
                  }
                  else
                  {
                    CcspTraceDebug(("pValue->parameterName, pValue->parameterValue attains NULL\n"));
                    return -1;
                  }  

			for( j= 0; j < (int)pThisObject->nCacheMibCount; j ++)
			{
                               
				if( pValue->parameterName != NULL )
                                {
                                    rc = strcmp_s(pThisObject->CacheDMName[j],strlen(pThisObject->CacheDMName[j]),pValue->parameterName,&ind);
                                    ERR_CHK(rc);
                                   if ((!ind) && (rc == EOK))
			           {
					pMibValue = CcspUtilLookforMibValueObjWithOid(&pThisObject->MibValueQueue, pThisObject->CacheMibOid[j]);
					pMapping  = CcspUtilLookforMibMapWithOid(&pThisObject->MibObjQueue, pThisObject->CacheMibOid[j]);

					if( (pMibValue != NULL) && (pMapping != NULL) && (pValue->parameterValue != NULL) )
					{
					   /* Copy the value */
					   CcspUtilDMValueToMIB(pMapping, pMibValue, (int)pValue->type, (char*)pValue->parameterValue);
					}
                                        else
                                        {
                                           CcspTraceDebug(("pMapping,pMibValue,pValue->parameterValue are attained NULL\n"));
                                            return -1;
                                        }
                                        
			             
				   }
                                }
			}
		}

		/* free the parameter values */
		Cosa_FreeParamValues(size, paramValues);
     }

	return 0;
}

/**********************************************************************

    prototype:

		void
		CcspScalarHelperClearCache
			(
				ANSC_HANDLE                 hThisObject
			);

    description:

        One of the cache handler function to clear values in cache.

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

	return:     None

**********************************************************************/
void
CcspScalarHelperClearCache
	(
        ANSC_HANDLE                 hThisObject
	)
{
        UNREFERENCED_PARAMETER(hThisObject);
	/* there's nothing to do for now */
}
