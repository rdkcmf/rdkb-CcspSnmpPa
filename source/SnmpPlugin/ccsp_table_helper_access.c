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

		*   CcspTableHelperSetMibValues
		*   CcspTableHelperGetMibValues
		*   CcspTableHelperRefreshCache

  ------------------------------------------------------------------------------

    revision:

        05/14/2012    initial revision.

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

#include "cosa_api.h"

/**********************************************************************

    prototype:

		int
		CcspTableHelperGetMibValues
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
CcspTableHelperGetMibValues
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	)
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject     = (PCCSP_TABLE_HELPER_OBJECT)hThisObject;
	PCCSP_MIB_VALUE                 pMibValueObj    = (PCCSP_MIB_VALUE)NULL;
    netsnmp_request_info            *request		= NULL;
    netsnmp_variable_list           *requestvb		= NULL;
    oid                             subid			= 0;
    netsnmp_table_request_info*		table_info      = NULL;
    netsnmp_tdata*					table_data      = NULL;
    netsnmp_tdata_row*				table_row       = NULL;
    PCCSP_TABLE_ENTRY				table_entry     = NULL;


    for (request = requests; request != NULL; request = request->next) 
	{
		if( request->processed != 0) { continue;}

            table_entry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
            table_info = netsnmp_extract_table_info(request);
			subid = table_info->colnum;

			if(!table_entry)
			{
				netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
				continue;
			}

			requestvb = request->requestvb;
			pMibValueObj = CcspUtilLookforMibValueObjWithOid(&table_entry->MibValueQueue, subid);

			if( pMibValueObj != NULL)
			{
				if( pMibValueObj->uType == ASN_INTEGER || pMibValueObj->uType == ASN_BOOLEAN ||
					(pMibValueObj->uType >= ASN_IPADDRESS && pMibValueObj->uType <= ASN_OPAQUE))
				{
					pMibValueObj->uSize = 4;
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
		CcspTableHelperSetMibValues
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
		if( pMapping->MibInfo.uType == ASN_INTEGER || pMapping->MibInfo.uType == ASN_UNSIGNED)
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
tableGroupSetReserve2
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	)
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject     = (PCCSP_TABLE_HELPER_OBJECT)hThisObject;
	PCCSP_MIB_VALUE                 pMibValueObj    = (PCCSP_MIB_VALUE)NULL;
    netsnmp_request_info            *request		= NULL;
    netsnmp_variable_list           *requestvb		= NULL;
	PCCSP_MIB_MAPPING				pMapping        = NULL;
    oid                             subid			= 0;
	int								i               = 0;
	ULONG							uCount          = 0;
	parameterValStruct_t*			pValueArray	    = NULL;
	BOOL							bResult         = FALSE;
	PCCSP_TABLE_ENTRY				pEntry          = (PCCSP_TABLE_ENTRY)NULL;
	netsnmp_table_request_info*     table_info      = NULL;
	netsnmp_tdata*					table_data      = NULL;
	netsnmp_tdata_row*			    table_row       = NULL;
	ULONG                           indexes[8]      = { 0 };

	/* first round check how many parameters will be set */
	for (request = requests; request != NULL; request = request->next) 
	{
		if( request->processed != 0) { continue;}

		pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
		table_info = netsnmp_extract_table_info(request);

		requestvb = request->requestvb;
		subid     = table_info->colnum;
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
	pValueArray = (parameterValStruct_t*)AnscAllocateMemory(sizeof(parameterValStruct_t)* uCount);

	if( pValueArray == NULL)
	{
		return SNMP_ERR_GENERR;
	}

	/* Second round to transfer mib value to DM value */
	uCount = 0;
	for (request = requests; request != NULL; request = request->next) 
	{
		if( request->processed != 0) { continue;}

		pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
		table_info = netsnmp_extract_table_info(request);

		if( pEntry == NULL)  return SNMP_ERR_NOERROR;

		requestvb = request->requestvb;
		subid     = table_info->colnum;
		pMapping  = CcspUtilLookforMibMapWithOid(&pThisObject->MibObjQueue, subid);
		pMibValueObj = CcspUtilLookforMibValueObjWithOid(&pEntry->MibValueQueue, subid);

		for( i = 0; i < pEntry->IndexCount; i ++)
		{
			indexes[i] = pEntry->IndexValue[i].Value.uValue;
		}

		if( pMapping && pMapping->bHasMapping)
		{
			pValueArray[uCount].parameterName = CcspUtilGetDMParamName(&pThisObject->IndexMapQueue, indexes, pEntry->IndexCount, pMapping->Mapping.pDMName);
			pValueArray[uCount].type          = (enum dataType_e)pMapping->Mapping.uDataType;

			if( pMibValueObj != NULL)
			{
				if( pMapping->MibInfo.uType == ASN_OCTET_STR)
				{
					pMibValueObj->BackValue.pBuffer = pMibValueObj->Value.pBuffer;
					pMibValueObj->uBackSize         = pMibValueObj->uSize;

					pMibValueObj->Value.pBuffer     = AnscCloneString((char*)requestvb->val.string);
					pMibValueObj->uSize             = requestvb->val_len;
				}
				else if( pMapping->MibInfo.uType == ASN_BIT_STR)
				{
					pMibValueObj->BackValue.puBuffer  = pMibValueObj->Value.puBuffer;
					pMibValueObj->uBackSize           = pMibValueObj->uSize;

					pMibValueObj->Value.puBuffer      = (u_char*)AnscAllocateMemory(requestvb->val_len);
					if( pMibValueObj->Value.puBuffer != NULL) AnscCopyMemory(pMibValueObj->Value.puBuffer, requestvb->val.bitstring, requestvb->val_len);
					pMibValueObj->uSize               = requestvb->val_len;
				}
				else
				{
					pMibValueObj->BackValue.uValue  = pMibValueObj->Value.uValue;
					pMibValueObj->uBackSize         = pMibValueObj->uSize;

					pMibValueObj->Value.uValue     = *requestvb->val.integer;
					pMibValueObj->uSize             = requestvb->val_len;
				}
			}

			/* parse MIB value to DM value */
			CcspUtilMIBValueToDM(pMapping, (void*)&pValueArray[uCount], request->requestvb);
			pThisObject->bBackground |= pMapping->Mapping.backgroundCommit;
			CcspTraceDebug(("!!!!!Background commit %d (table)\n",pThisObject->bBackground));
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
		for( i = 0; i < uCount; i ++)
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
tableGroupSetFree
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	)
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject     = (PCCSP_TABLE_HELPER_OBJECT)hThisObject;
	PCCSP_MIB_VALUE                 pMibValueObj    = (PCCSP_MIB_VALUE)NULL;
    netsnmp_request_info            *request		= NULL;
    netsnmp_variable_list           *requestvb		= NULL;
    oid                             subid			= 0;
	PCCSP_TABLE_ENTRY				pEntry          = (PCCSP_TABLE_ENTRY)NULL;
	netsnmp_table_request_info*     table_info      = NULL;
	netsnmp_tdata*					table_data      = NULL;
	netsnmp_tdata_row*			    table_row       = NULL;
	ULONG                           indexes[8]      = { 0 };
	ULONG							i				= 0;

	AnscTraceInfo(("Enter 'tableGroupSetFree'\n"));

#if 0
	/* check whether Rowstatus is involved */
	for (request = requests; request != NULL; request = request->next) 
	{
		if( request->processed != 0) { continue;}

		pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
		table_info = netsnmp_extract_table_info(request);
		table_data = netsnmp_tdata_extract_table(request);
		table_row  = netsnmp_tdata_extract_row(request);

		requestvb = request->requestvb;
		subid     = table_info->colnum;

		if( subid == pThisObject->uRowStatus)
		{
			if( RS_CREATEANDGO == *requestvb->val.integer || RS_CREATEANDWAIT == *requestvb->val.integer)
			{
				if( pEntry != NULL && !pEntry->valid)
				{
					for( i = 0; i < pEntry->IndexCount; i ++)
					{
						indexes[i] = pEntry->IndexValue[i].Value.uValue;
					}

					/* remove the entry at the back-end */
					if(!CcspUtilDeleteCosaEntry((ANSC_HANDLE)pThisObject, indexes, pEntry->IndexCount))
					{
						AnscTraceWarning(("Failed to delete DM entry.\n"));
					}
					CcspUtilRemoveMibEntry(table_data,table_row);

				}
			}

		}
	}
#endif

	/* Copy back the saved values */
	for (request = requests; request != NULL; request = request->next) 
	{
		if( request->processed != 0) { continue;}

		pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
		table_info = netsnmp_extract_table_info(request);

		requestvb = request->requestvb;
		subid     = table_info->colnum;

		if( pEntry == NULL) return SNMP_ERR_NOERROR;

		pMibValueObj = CcspUtilLookforMibValueObjWithOid(&pEntry->MibValueQueue, subid);

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
			else if( pMibValueObj->uType == ASN_BIT_STR)
			{
				if( pMibValueObj->Value.puBuffer != NULL)  AnscFreeMemory(pMibValueObj->Value.puBuffer);

				pMibValueObj->Value.puBuffer     = pMibValueObj->BackValue.puBuffer;
				pMibValueObj->uSize              = pMibValueObj->uBackSize;

				pMibValueObj->BackValue.puBuffer = NULL;
				pMibValueObj->uBackSize          = 0;
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

	return SNMP_ERR_NOERROR;
}

int
CcspTableHelperSetMibValues
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	)
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject     = (PCCSP_TABLE_HELPER_OBJECT)hThisObject;
	PCCSP_TABLE_ENTRY				pEntry          = (PCCSP_TABLE_ENTRY)NULL;
	PCCSP_MIB_VALUE                 pMibValueObj    = (PCCSP_MIB_VALUE)NULL;
    netsnmp_request_info            *request		= NULL;
	netsnmp_table_request_info*     table_info      = NULL;
	netsnmp_tdata*					table_data      = NULL;
	netsnmp_tdata_row*			    table_row       = NULL;
    netsnmp_variable_list           *requestvb		= NULL;
    netsnmp_variable_list           *next    		= NULL;
	PCCSP_MIB_MAPPING				pMapping        = NULL;
    oid                             subid			= 0;
	int								ret             = 0;
	int                             i               = 0;
	ULONG                           indexes[8]      = { 0 };

	AnscTraceInfo(("Enter 'CcspTableHelperSetMibValues' with mode = %d\n", reqinfo->mode));

	switch( reqinfo->mode)
	{
		case MODE_SET_RESERVE1:

			for (request = requests; request != NULL; request = request->next) 
			{
				if( request->processed != 0) { continue;}

				pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
				table_info = netsnmp_extract_table_info(request);

				requestvb = request->requestvb;
				subid     = table_info->colnum;

				pMapping  = CcspUtilLookforMibMapWithOid(&pThisObject->MibObjQueue, subid);

				if( subid == pThisObject->uRowStatus)
				{
					ret = netsnmp_check_vb_rowstatus( requestvb, (pEntry? RS_ACTIVE: RS_NONEXISTENT));

					if( ret != SNMP_ERR_NOERROR)
					{
						netsnmp_set_request_error(reqinfo, request, ret);

						return SNMP_ERR_NOERROR;
					}

					/* somehow the Destroy was not checked correctly above */
					if( pEntry == NULL && *requestvb->val.integer == RS_DESTROY)
					{
						netsnmp_set_request_error(reqinfo, request, SNMP_ERR_BADVALUE);

						return SNMP_ERR_NOERROR;
					}
				}
				else if( pMapping)
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

			for (request = requests; request != NULL; request = request->next) 
			{
				if( request->processed != 0) { continue;}

				pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);
				table_info = netsnmp_extract_table_info(request);
				table_data = netsnmp_tdata_extract_table(request);

				requestvb = request->requestvb;
				subid     = table_info->colnum;

				if( subid == pThisObject->uRowStatus)
				{
					if( RS_CREATEANDGO == *requestvb->val.integer || RS_CREATEANDWAIT == *requestvb->val.integer)
					{
						next = table_info->indexes;

						for( i = 0; i < table_info->number_indexes; i ++)
						{
							indexes[i] = *next->val.integer;
							next = next->next_variable;

							if( next == NULL) break;
						}

						table_row = CcspUtilCreateMibEntry( table_data, indexes, table_info->number_indexes, FALSE);

						if( table_row)
						{
							/* create entry at CCSP back-end */
							if(!CcspUtilCreateCosaEntry((ANSC_HANDLE)pThisObject, indexes, table_info->number_indexes))
							{
								AnscTraceError(("Failed to Add COSA Entry at back-end.\n"));
							}

							pEntry = (PCCSP_TABLE_ENTRY)table_row->data;

							/* the indexes array is the array of CCSP instance numbers */
							for( i = 0; i < table_info->number_indexes; i ++)
							{
								pEntry->IndexValue[i].Value.iValue = indexes[i];
							}

							pEntry->IndexCount = table_info->number_indexes;

							/* init the value array */
							CcspUtilInitMibValueArray(&pThisObject->MibObjQueue, &pEntry->MibValueQueue);

							netsnmp_insert_tdata_row(request, table_row);
						}
						else
						{
							netsnmp_set_request_error(reqinfo, request, SNMP_ERR_RESOURCEUNAVAILABLE);

							return SNMP_ERR_NOERROR;
						}
					}
				}
			}

			/* collect all the updated values and call Cosa_SetParamValues with Commit = FALSE */
			return tableGroupSetReserve2(hThisObject, reqinfo, requests);

			break;

		case MODE_SET_ACTION:

			if( pThisObject->pCcspComp != NULL && pThisObject->pCcspPath)
			{
				/* commit the update */
				if (pThisObject->bBackground) 
				{
					Cosa_BackgroundCommit(pThisObject->pCcspComp, pThisObject->pCcspPath, TRUE);
					pThisObject->bBackground = 0;
				}
				else
				{
					Cosa_SetCommit(pThisObject->pCcspComp, pThisObject->pCcspPath, TRUE);
				}
			}

			for (request = requests; request != NULL; request = request->next) 
			{
				if( request->processed != 0) { continue;}

				pEntry = (PCCSP_TABLE_ENTRY)netsnmp_tdata_extract_entry(request);

				if(pEntry)
				{
					table_info = netsnmp_extract_table_info(request);
					table_row  = netsnmp_tdata_extract_row(request);
					table_data = netsnmp_tdata_extract_table(request);

					requestvb = request->requestvb;
					subid     = table_info->colnum;

					if( subid == pThisObject->uRowStatus)
					{
						pMibValueObj = CcspUtilLookforMibValueObjWithOid(&pEntry->MibValueQueue, subid);

						switch(*requestvb->val.integer)
						{
							case RS_CREATEANDGO:
								pEntry->valid = 1;
							case RS_ACTIVE:
								if( pMibValueObj) pMibValueObj->Value.uValue = RS_ACTIVE;
									break;
							case RS_CREATEANDWAIT:
								pEntry->valid = 1;
							case RS_NOTINSERVICE:
								if( pMibValueObj) pMibValueObj->Value.uValue = RS_NOTINSERVICE;
								break;
							case RS_DESTROY:

								for( i = 0; i < pEntry->IndexCount; i ++)
								{
									indexes[i] = pEntry->IndexValue[i].Value.uValue;
								}

								/* remove the entry at the back-end */
								if(!CcspUtilDeleteCosaEntry((ANSC_HANDLE)pThisObject, indexes, pEntry->IndexCount))
								{
									AnscTraceWarning(("Failed to delete DM entry.\n"));
								}

								CcspUtilRemoveMibEntry(table_data,table_row);

								break;
						}
					}
				}
			}

			return SNMP_ERR_NOERROR;

		case MODE_SET_FREE:

			if( pThisObject->pCcspComp != NULL && pThisObject->pCcspPath)
			{
				/* don't commit the update */
				Cosa_SetCommit(pThisObject->pCcspComp, pThisObject->pCcspPath, FALSE);
			}

		   return tableGroupSetFree(hThisObject, reqinfo, requests); 

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
		CcspTableHelperRefreshCache
			(
				ANSC_HANDLE                 hThisObject
			);

    description:

        One of the cache handler function to load values for cache.

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

	return:     The result of refresh cache

**********************************************************************/
static
BOOL
tableGroupGetCosaValues
	(
		ANSC_HANDLE					hThisObject, 
		PCCSP_TABLE_ENTRY			pEntry
	)
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject     = (PCCSP_TABLE_HELPER_OBJECT)hThisObject;
	int								size			= 0;
	parameterValStruct_t**			paramValues	    = NULL;
	parameterValStruct_t*			pValue          = NULL;
	int								i				= 0;
	int								j               = 0;
	char*                           CacheDMName[MAXI_MIB_COUNT_IN_GROUP]  = { 0 };        
	ULONG                           CacheMibOid[MAXI_MIB_COUNT_IN_GROUP]  = { 0 };        
	ULONG							nCacheMibCount  = 0;
	char							pTemp[256]      = { 0 };
	PCCSP_MIB_MAPPING				pMibMap			= (PCCSP_MIB_MAPPING)NULL;
	PSINGLE_LINK_ENTRY              pSLinkEntry     = (PSINGLE_LINK_ENTRY)NULL;
	PCCSP_MIB_VALUE					pMibValue       = (PCCSP_MIB_VALUE)NULL;
	BOOL							bReturn         = FALSE;

	pSLinkEntry = AnscQueueGetFirstEntry(&pThisObject->MibObjQueue);

	while ( pSLinkEntry )
	{
		pMibMap         = ACCESS_CCSP_MIB_MAPPING(pSLinkEntry);
		pSLinkEntry     = AnscQueueGetNextEntry(pSLinkEntry);

		if( pMibMap != NULL && pMibMap->bHasMapping)
		{
			/* add the DM name to cache array */
			if(nCacheMibCount < MAXI_MIB_COUNT_IN_GROUP)
			{
				if( pEntry->IndexCount == 1)
				{
					_ansc_sprintf(pTemp, pMibMap->Mapping.pDMName, 
                            pEntry->IndexValue[0].Value.iValue);
				}
				else if( pEntry->IndexCount == 2)
				{
					_ansc_sprintf(pTemp, pMibMap->Mapping.pDMName,
                            pEntry->IndexValue[0].Value.iValue,
                            pEntry->IndexValue[1].Value.iValue);
				}
				else if( pEntry->IndexCount == 3)
				{
					_ansc_sprintf(pTemp, pMibMap->Mapping.pDMName,
                            pEntry->IndexValue[0].Value.iValue,
                            pEntry->IndexValue[1].Value.iValue,
                            pEntry->IndexValue[2].Value.iValue);
				}
				else if( pEntry->IndexCount == 4)
				{
					_ansc_sprintf(pTemp, pMibMap->Mapping.pDMName,
                            pEntry->IndexValue[0].Value.iValue,
                            pEntry->IndexValue[1].Value.iValue,
                            pEntry->IndexValue[2].Value.iValue,
                            pEntry->IndexValue[3].Value.iValue);
				}

				CacheDMName[nCacheMibCount] = AnscCloneString(pTemp);
				CacheMibOid[nCacheMibCount] = pMibMap->MibInfo.uLastOid;
				nCacheMibCount ++;

				AnscTraceInfo(("Add cache: %s\n", pTemp));
			}
		}
	}

#if 0
	if( !Cosa_GetParamValues(pThisObject->pCcspComp, pThisObject->pCcspPath, CacheDMName, nCacheMibCount, &size, &paramValues))
	{
		AnscTraceError(("Failed to get value from CCSP components.\n"));
		goto EXIT;
	}

	/* put them in the value array */
	for( i = 0; i< size; i ++)
	{
		pValue = paramValues[i];

        if (pValue->parameterName && pValue->parameterValue)
            CcspTraceDebug(("  %s %s\n", pValue->parameterName, pValue->parameterValue));

		for( j= 0; j < nCacheMibCount; j ++)
		{
			if( pValue->parameterName != NULL && AnscEqualString(pValue->parameterName, CacheDMName[j], TRUE))
			{
				pMibValue = CcspUtilLookforMibValueObjWithOid(&pEntry->MibValueQueue, CacheMibOid[j]);
				pMibMap   = CcspUtilLookforMibMapWithOid(&pThisObject->MibObjQueue, CacheMibOid[j]);

				if( pMibValue != NULL && pMibMap != NULL)
				{
					/* Copy the value */
					CcspUtilDMValueToMIB(pMibMap, pMibValue, (int)pValue->type, (char*)pValue->parameterValue);
				}
			}
		}
	}

	/* free the parameter values */
	Cosa_FreeParamValues(size, paramValues);


#else
	/* put them in the value array */
	for( i = 0; i< nCacheMibCount; i ++)
	{
		size = 0;
		paramValues = NULL;

		/* get value one by one instead all to bypass any parameter with error */
		if( !Cosa_GetParamValues(pThisObject->pCcspComp, pThisObject->pCcspPath, &CacheDMName[i], 1, &size, &paramValues))
		{
			AnscTraceError(("Failed to get value of '%s'\n", CacheDMName[i]));
		}
		else
		{
			pValue = paramValues[0];

			if (pValue->parameterName && pValue->parameterValue)
				CcspTraceDebug(("  %s %s\n", pValue->parameterName, pValue->parameterValue));

			pMibValue = CcspUtilLookforMibValueObjWithOid(&pEntry->MibValueQueue, CacheMibOid[i]);
			pMibMap   = CcspUtilLookforMibMapWithOid(&pThisObject->MibObjQueue, CacheMibOid[i]);

			if( pMibValue != NULL && pMibMap != NULL)
			{
				/* Copy the value */
				CcspUtilDMValueToMIB(pMibMap, pMibValue, (int)pValue->type, (char*)pValue->parameterValue);
			}
		}

		/* free the parameter values */
		Cosa_FreeParamValues(size, paramValues);
	}

#endif

    bReturn = TRUE;

EXIT:

	for( i = 0; i < nCacheMibCount; i ++)
	{
		if( CacheDMName[i] != NULL)
		{
			AnscFreeMemory(CacheDMName[i]);
		}
	}

	return bReturn;
}

static int
tableGroupGetSubDMMapping
	(
        ANSC_HANDLE     hThisObject,
	char*		pSubDM,
        int             indexes[3]
        )
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject     = (PCCSP_TABLE_HELPER_OBJECT)hThisObject;
	int								size			= 0;
	parameterValStruct_t**			paramValues	    = NULL;
	parameterValStruct_t*			pValue          = NULL;
	char							pTemp[256]      = { 0 };
	char*							pSubDMName = pTemp;
	int							iReturn         = 0;
	int 					uDMType;

	_ansc_sprintf(pTemp, pSubDM, indexes[0], indexes[1], indexes[2]);

	if( !Cosa_GetParamValues(pThisObject->pCcspComp, pThisObject->pCcspPath, &pSubDMName, 1, &size, &paramValues))
	{
		AnscTraceError(("Failed to get value of '%s'\n", pTemp));
	}
	else
	{
		pValue = paramValues[0];

		if (pValue->parameterName && pValue->parameterValue)
			CcspTraceDebug(("Index SubDM:  %s %s\n", pValue->parameterName, pValue->parameterValue));
		uDMType = (int)pValue->type;

		if( uDMType == ccsp_int || uDMType == ccsp_long || uDMType == ccsp_unsignedInt || uDMType == ccsp_unsignedLong)
		{
			iReturn = atoi(pValue->parameterValue);
		}
		else
		{
			AnscTraceError(("Index SubDM, Invalid data type. %s %s\n", pValue->parameterName, pValue->parameterValue));
		}
	}
	Cosa_FreeParamValues(size, paramValues);

	return iReturn;
}

int
CcspTableHelperRefreshCache
	(
        ANSC_HANDLE                 hThisObject
	)
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject     = (PCCSP_TABLE_HELPER_OBJECT)hThisObject;
	char*							pDMString       = pThisObject->pStrSampleDM;
	char*							pDestComp       = NULL;
	char*							pDestPath       = NULL;
	PCCSP_MIB_MAPPING				pMibMap			= (PCCSP_MIB_MAPPING)NULL;
	PCCSP_INDEX_MAPPING				pIndexMap		= (PCCSP_INDEX_MAPPING)NULL;
	PSINGLE_LINK_ENTRY              pSLinkEntry     = (PSINGLE_LINK_ENTRY)NULL;
	char                            pTemp[256]      = { 0 };
	netsnmp_tdata*					table			= (netsnmp_tdata *)pThisObject->mibMagic.pTableData;
    netsnmp_tdata_row*				row				= NULL;
	PCCSP_TABLE_ENTRY				pEntry          = NULL;
	ULONG							indexes[6]      = { 0 };
	int							    indexCount      = pThisObject->IndexMapQueue.Depth;
	int								i				= 0;
	int								j				= 0;
	int								k				= 0;
	char*							pFind           = NULL;
	unsigned int*				    insArray1       = NULL;
	unsigned int					insCount1       = 32;
	unsigned int*					insArray2       = NULL;
	unsigned int					insCount2       = 32;
	unsigned int*					insArray3       = NULL;
	unsigned int					insCount3       = 32;
	unsigned int					subDMIns[3] = {0,0,0};
    int                             status          = 0;

    if (pThisObject->RefreshCacheCallback != NULL)
    {
        int (*TableRefreshCache)(netsnmp_tdata *);

        TableRefreshCache = pThisObject->RefreshCacheCallback;
        status = TableRefreshCache(table);
    }

    if(pThisObject->bCacheSkip == TRUE)
    {
        return status;
    }

#if 0

	for( i = 0; i < 3; i ++)
	{
		for( j = 0; j < indexCount; j ++)
 		{
			indexes[j] = 5 + i + j; 
		}

        row = CcspUtilCreateMibEntry(table, indexes, indexCount, TRUE);
		
        if (row == NULL)  continue;

		pEntry = (PCCSP_TABLE_ENTRY)row->data;

		/* init the value array */
		CcspUtilInitMibValueArray(&pThisObject->MibObjQueue, &pEntry->MibValueQueue);
    }


#else

	/* first time we need to figure out which component to talk with */
	if( !pThisObject->pCcspComp || !pThisObject->pCcspPath)
	{
		if( pDMString == NULL)
		{
			AnscTraceWarning(("No one DM param name is configured, no way to cache.\n"));

			return -1;
		}
		else
		{
			/* remove the chars after '%d' */
			pFind = _ansc_strstr(pDMString, "%d");

			if( pFind != NULL)
			{
				pDMString[(ULONG)(pFind - pDMString)] = '\0';
			}

			AnscTraceInfo(("Try to find the CCSP component who supports '%s'\n", pDMString));
		}

		if( !Cosa_FindDestComp(pDMString, &pThisObject->pCcspComp, &pThisObject->pCcspPath) )
		{
			AnscTraceWarning(("Failed to find the CCSP component who supports '%s'\n", pDMString));

			return -1;
		}
	}

	if( pThisObject->MibObjQueue.Depth == 0 || pThisObject->IndexMapQueue.Depth == 0)
	{
		AnscTraceError(("No one mib or index is loaded in the mib table, cache failed.\n"));

		return -1;
	}

	if( pThisObject->IndexMapQueue.Depth == 1)
	{
		pSLinkEntry = AnscQueueGetFirstEntry(&pThisObject->IndexMapQueue);

		pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);

		if( pIndexMap != NULL)
		{
			if(pIndexMap->uMapType >= CCSP_MIB_MAP_TO_DM)
			{
				AnscCopyString(pTemp, pIndexMap->Mapping.DMMappingInfo.pDMName);
		
				/* get the ins count */
				if( !Cosa_GetInstanceNums(pThisObject->pCcspComp, pThisObject->pCcspPath, pTemp, &insArray1, &insCount1))
				{
					AnscTraceWarning(("Failed to GetInstanceNums of '%s'\n", pTemp));
                    insArray1 = NULL;
                    insCount1 = 0;
				}

				for( i = 0; i < insCount1; i ++)
				{
					indexCount = 1;
                                        if (pIndexMap->uMapType == CCSP_MIB_MAP_TO_INSNUMBER) {
						indexes[0] = CcspUtilLookforInsNumMapping(&pIndexMap->IndexQueue, insArray1[i], FALSE);
						if( indexes[0] == 0 && pIndexMap->IndexQueue.Depth > 0)
						{
							AnscTraceError(("Unable to find the insNumber to index mapping for '%d'\n", insArray1[i]));
						}
					} else if (pIndexMap->uMapType == CCSP_MIB_MAP_TO_SUBDM) {
						subDMIns[0] = insArray1[i];
						indexes[0] = tableGroupGetSubDMMapping(pThisObject, pIndexMap->Mapping.SubDMMappingInfo.pSubDMName, subDMIns);
						if( indexes[0] == 0 )
						{
							AnscTraceError(("Unable to find the sub DM value to index mapping for '%d'\n", insArray1[i]));
						}
					}

					if( indexes[0] == 0)
						indexes[0] = insArray1[i];

					row = CcspUtilCreateMibEntry(table, indexes, indexCount, TRUE);
		
					if (row == NULL)  continue;

					pEntry = (PCCSP_TABLE_ENTRY)row->data;

					/* don't forget to set back the actual instance number at back-end */
					pEntry->IndexValue[0].Value.iValue = insArray1[i];
					pEntry->IndexCount = 1;

					/* init the value array */
					CcspUtilInitMibValueArray(&pThisObject->MibObjQueue, &pEntry->MibValueQueue);

					/* retrieve values from back-end Component */
					if(!tableGroupGetCosaValues(pThisObject, pEntry))
					{
						AnscTraceError(("Failed to get COSA values.\n"));
					}
				}

                if (insArray1)
                    free(insArray1);
			}
			else
			{
				AnscTraceInfo(("Unsupported MIB index mapping type: %lu\n", pIndexMap->uMapType));
			}
		}
	}
	else if(pThisObject->IndexMapQueue.Depth == 2)
	{
		pSLinkEntry = AnscQueueGetFirstEntry(&pThisObject->IndexMapQueue);
		pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);

		if( pIndexMap != NULL)
		{
			if(pIndexMap->uMapType >= CCSP_MIB_MAP_TO_DM)
			{
				AnscCopyString(pTemp, pIndexMap->Mapping.DMMappingInfo.pDMName);
		
				/* get the ins count */
				if( !Cosa_GetInstanceNums(pThisObject->pCcspComp, pThisObject->pCcspPath, pTemp, &insArray1, &insCount1))
				{
					AnscTraceWarning(("Failed to GetInstanceNums of '%s'\n", pTemp));
                    insArray1 = NULL;
                    insCount1 = 0;
				}

				for( i = 0; i < insCount1; i ++)
				{
					indexes[0] = CcspUtilLookforInsNumMapping(&pIndexMap->IndexQueue, insArray1[i], FALSE);
					indexCount = 1;

					if( indexes[0] == 0)
					{
						if( pIndexMap->IndexQueue.Depth > 0)
						{
							AnscTraceError(("Unable to find the insNumber to index mapping for '%d'\n", insArray1[i]));
						}

						indexes[0] = insArray1[i];
					}

					/* get the second index */
					pSLinkEntry = AnscQueueSearchEntryByIndex(&pThisObject->IndexMapQueue,1);
					pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);

					if( pIndexMap != NULL)
					{
						if(pIndexMap->uMapType >= CCSP_MIB_MAP_TO_DM)
						{
							/* AnscCopyString(pTemp, pIndexMap->Mapping.DMMappingInfo.pDMName); */
							_ansc_sprintf(pTemp, pIndexMap->Mapping.DMMappingInfo.pDMName, insArray1[i]);
		
							/* get the ins count */
							if( !Cosa_GetInstanceNums(pThisObject->pCcspComp, pThisObject->pCcspPath, pTemp, &insArray2, &insCount2))
							{
								AnscTraceWarning(("Failed to GetInstanceNums of '%s'\n", pTemp));
                                insArray2 = NULL;
                                insCount2 = 0;
							}

							for( j = 0; j < insCount2; j ++)
							{
								indexes[1] = CcspUtilLookforInsNumMapping(&pIndexMap->IndexQueue, insArray2[j], FALSE);
								indexCount = 2;

								if( indexes[1] == 0)
								{
									if( pIndexMap->IndexQueue.Depth > 0)
									{
										AnscTraceError(("Unable to find the insNumber to index mapping for '%d'\n", insArray2[j]));
									}

									indexes[1] = insArray2[j];
								}

								/* create the entry */
								row = CcspUtilCreateMibEntry(table, indexes, indexCount, TRUE);
		
								if (row == NULL)  continue;

								pEntry = (PCCSP_TABLE_ENTRY)row->data;

								/* don't forget to set back the actual instance number at back-end */
								pEntry->IndexValue[0].Value.iValue = insArray1[i];
								pEntry->IndexValue[1].Value.iValue = insArray2[j];
								pEntry->IndexCount = 2;

								/* init the value array */
								CcspUtilInitMibValueArray(&pThisObject->MibObjQueue, &pEntry->MibValueQueue);

								/* retrieve values from back-end Component */
								if(!tableGroupGetCosaValues(pThisObject, pEntry))
								{
									AnscTraceError(("Failed to get COSA values.\n"));
								}
							}
                            
                            

                            if (insArray2)
                                free(insArray2);
						}
					}
                    /*Reset mapping to first level index*/
                    pSLinkEntry = AnscQueueGetFirstEntry(&pThisObject->IndexMapQueue);
                    pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);
				}

                if (insArray1)
                    free(insArray1);
			}
			else
			{
				AnscTraceInfo(("Unsupported MIB index mapping type: %lu\n", pIndexMap->uMapType));
			}
		}
	}
	else if(pThisObject->IndexMapQueue.Depth == 3)
	{
		pSLinkEntry = AnscQueueGetFirstEntry(&pThisObject->IndexMapQueue);
		pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);

		if( pIndexMap != NULL)
		{
			if(pIndexMap->uMapType >= CCSP_MIB_MAP_TO_DM)
			{
				AnscCopyString(pTemp, pIndexMap->Mapping.DMMappingInfo.pDMName);
		
				/* get the ins count */
				if( !Cosa_GetInstanceNums(pThisObject->pCcspComp, pThisObject->pCcspPath, pTemp, &insArray1, &insCount1))
				{
					AnscTraceWarning(("Failed to GetInstanceNums of '%s'\n", pTemp));
                    insArray1 = NULL;
                    insCount1 = 0;
				}

				for( i = 0; i < insCount1; i ++)
				{
					indexes[0] = CcspUtilLookforInsNumMapping(&pIndexMap->IndexQueue, insArray1[i], FALSE);
					indexCount = 1;

					if( indexes[0] == 0)
					{
						if( pIndexMap->IndexQueue.Depth > 0)
						{
							AnscTraceError(("Unable to find the insNumber to index mapping for '%d'\n", insArray1[i]));
						}

						indexes[0] = insArray1[i];
					}

					/* get the second index */
					pSLinkEntry = AnscQueueSearchEntryByIndex(&pThisObject->IndexMapQueue,1);
					pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);

					if( pIndexMap != NULL)
					{
						if(pIndexMap->uMapType >= CCSP_MIB_MAP_TO_DM)
						{
							/* AnscCopyString(pTemp, pIndexMap->Mapping.DMMappingInfo.pDMName); */
							_ansc_sprintf(pTemp, pIndexMap->Mapping.DMMappingInfo.pDMName, insArray1[i]);
		
							/* get the ins count */
							if( !Cosa_GetInstanceNums(pThisObject->pCcspComp, pThisObject->pCcspPath, pTemp, &insArray2, &insCount2))
							{
								AnscTraceWarning(("Failed to GetInstanceNums of '%s'\n", pTemp));
                                insArray2 = NULL;
                                insCount2 = 0;
							}

							for( j = 0; j < insCount2; j ++)
							{
								indexes[1] = CcspUtilLookforInsNumMapping(&pIndexMap->IndexQueue, insArray2[j], FALSE);
								indexCount = 2;

								if( indexes[1] == 0)
								{
									if( pIndexMap->IndexQueue.Depth > 0)
									{
										AnscTraceError(("Unable to find the insNumber to index mapping for '%d'\n", insArray2[j]));
									}

									indexes[1] = insArray2[j];
								}

								/* get the third index */
								pSLinkEntry = AnscQueueSearchEntryByIndex(&pThisObject->IndexMapQueue,2);
								pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);

								if( pIndexMap != NULL)
								{
									if(pIndexMap->uMapType >= CCSP_MIB_MAP_TO_DM)
									{
										/* AnscCopyString(pTemp, pIndexMap->Mapping.DMMappingInfo.pDMName); */
										_ansc_sprintf(pTemp, pIndexMap->Mapping.DMMappingInfo.pDMName, insArray1[i], insArray2[j]);
		
										/* get the ins count */
										if( !Cosa_GetInstanceNums(pThisObject->pCcspComp, pThisObject->pCcspPath, pTemp, &insArray3, &insCount3))
										{
											AnscTraceWarning(("Failed to GetInstanceNums of '%s'\n", pTemp));
                                            insArray3 = NULL;
                                            insCount3 = 0;
										}

										for( k = 0; k < insCount3; k ++)
										{
											indexes[2] = CcspUtilLookforInsNumMapping(&pIndexMap->IndexQueue, insArray3[k], FALSE);
											indexCount = 3;

											if( indexes[2] == 0)
											{
												if( pIndexMap->IndexQueue.Depth > 0)
												{
													AnscTraceError(("Unable to find the insNumber to index mapping for '%d'\n", insArray3[k]));
												}

												indexes[2] = insArray3[k];
											}

											/* create the entry */
											row = CcspUtilCreateMibEntry(table, indexes, indexCount, TRUE);
		
											if (row == NULL)  continue;

											pEntry = (PCCSP_TABLE_ENTRY)row->data;

											/* don't forget to set back the actual instance number at back-end */
											pEntry->IndexValue[0].Value.iValue = insArray1[i];
											pEntry->IndexValue[1].Value.iValue = insArray2[j];
											pEntry->IndexValue[2].Value.iValue = insArray3[k];
											pEntry->IndexCount = 3;

											/* init the value array */
											CcspUtilInitMibValueArray(&pThisObject->MibObjQueue, &pEntry->MibValueQueue);

											/* retrieve values from back-end Component */
											if(!tableGroupGetCosaValues(pThisObject, pEntry))
											{
												AnscTraceError(("Failed to get COSA values.\n"));
											}
										}

                                        if (insArray3)
                                            free(insArray3);
									}
								}
                                pSLinkEntry = AnscQueueSearchEntryByIndex(&pThisObject->IndexMapQueue,1);
                                pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);
							}

                            if (insArray2)
                                free(insArray2);
						}
					}
                    pSLinkEntry = AnscQueueGetFirstEntry(&pThisObject->IndexMapQueue);
                    pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);
				}

                if (insArray1)
                    free(insArray1);
			}
			else
			{
				AnscTraceInfo(("Unsupported MIB index mapping type: %ld\n", pIndexMap->uMapType));
			}
		}
	}

#endif

	return 0;
}

