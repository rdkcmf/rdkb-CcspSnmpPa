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

        This is the implementation of utility functions used by
		CCSP SnmpAgent MIB Helper

        *   CcspUtilCleanMibValueQueue
		*	CcspUtilCleanMibObjQueue	
		*	CcspUtilCleanIndexMapQueue
		*   CcspUtilCleanMibMapping
		*   CcspUtilCleanIndexMapping
		*	CcspUtilParseOidValueString
		*	CcspUtilMIBStringToDataType
		*	CcspUtilTR69StringToDataType
		*	CcspUtilTR69DataTypeToString
		*	CcspUtilLoadMibInfo
		*	CcspUtilLoadDMMappingInfo
		*	CcspUtilLoadIndexMappingInfo
		*	CcspUtilLoadMibMappingInfo
		*	CcspUtilLoadIndexMapping
		*	CcspUtilPaseEnumString
		*	CcspUtilTraceOid
		*	CcspUtilInitMibValueArray
		*	CcspUtilLookforMibValueObjWithOid
		*	CcspUtilLookforMibMapWithOid
		*	CcspUtilLookforEnumMapping
		*	CcspUtilLookforInsNumMapping
		*   CcspUtilDMFilterToNamespace
		*	CcspUtilLookforEnumStrInMapping
		*	CcspUtilDMValueToMIB
		*	CcspUtilMIBValueToDM
		*	CcspUtilCreateMibEntry
		*	CcspUtilRemoveMibEntry
		*	CcspUtilDeleteCosaEntry
		*   CcspUtilCreateCosaEntry
		*   CcspUtilMibIndexesToInsArray
		*   CcspUtilAddIndexToInsMapping
	
  ------------------------------------------------------------------------------

    revision:

        05/02/2012    initial revision.

**********************************************************************************/
#include "ansc_platform.h"
#include "ccsp_mib_helper.h"
#include "ccsp_scalar_helper.h"
#include "ccsp_table_helper.h"
#include "ccsp_mib_utilities.h"

#include "ansc_xml_dom_parser_interface.h"
#include "ansc_xml_dom_parser_external_api.h"
#include "ansc_xml_dom_parser_status.h"

#include "ccsp_base_api.h"
#include "cosa_api.h"

#include "slap_definitions.h"
#include "slap_vco_global.h"
#include "slap_vho_exported_api.h"

#define MAX_OCTET_BUFFER_SIZE 256
#define MAX_BUFF_SIZE 1024
/**********************************************************************

    prototype:

		void
		CcspUtilCleanMibValueQueue
			(
				PQUEUE_HEADER               pQueue
			);

    description:

        This function is called to clean the Mib Value Queue;

    argument:   PQUEUE_HEADER               pQueue
	            The pointer of the queue;

	return:     None

**********************************************************************/
void
CcspUtilCleanMibValueQueue
    (
        PQUEUE_HEADER               pQueue
    )
{
    PSINGLE_LINK_ENTRY              pSLinkEntry  = (PSINGLE_LINK_ENTRY)NULL;
	PCCSP_MIB_VALUE				    pObj         = (PCCSP_MIB_VALUE)NULL;

    pSLinkEntry = AnscQueuePopEntry(pQueue);

    while ( pSLinkEntry )
    {
        pObj            = ACCESS_CCSP_MIB_VALUE(pSLinkEntry);
        pSLinkEntry     = AnscQueuePopEntry(pQueue);

		if( pObj != NULL)
		{
			if( pObj->uType == ASN_OCTET_STR)
			{
				if( pObj->Value.pBuffer != NULL)
				{
					AnscFreeMemory(pObj->Value.pBuffer);
					pObj->Value.pBuffer = NULL;
				}
				if( pObj->BackValue.pBuffer != NULL)
				{
					AnscFreeMemory(pObj->BackValue.pBuffer);
					pObj->BackValue.pBuffer = NULL;
				}
			}
			else if( pObj->uType == ASN_BIT_STR)
			{
				if( pObj->Value.puBuffer != NULL)
				{
					AnscFreeMemory(pObj->Value.puBuffer);
					pObj->Value.puBuffer = NULL;
				}
				if( pObj->BackValue.puBuffer != NULL)
				{
					AnscFreeMemory(pObj->BackValue.puBuffer);
					pObj->BackValue.puBuffer = NULL;
				}
			}

			AnscFreeMemory(pObj);
		}
    }

}

/**********************************************************************

    prototype:

		void
		CcspUtilCleanMibObjQueue
			(
				PQUEUE_HEADER               pQueue
			);

    description:

        This function is called to clean the Mib Object Queue;

    argument:   PQUEUE_HEADER               pQueue
	            The pointer of the queue;

	return:     None

**********************************************************************/
void
CcspUtilCleanMibObjQueue
    (
        PQUEUE_HEADER               pQueue
    )
{
    PSINGLE_LINK_ENTRY              pSLinkEntry  = (PSINGLE_LINK_ENTRY)NULL;
	PCCSP_MIB_MAPPING   		    pObj         = (PCCSP_MIB_MAPPING)NULL;

    pSLinkEntry = AnscQueuePopEntry(pQueue);

    while ( pSLinkEntry )
    {
        pObj            = ACCESS_CCSP_MIB_MAPPING(pSLinkEntry);
        pSLinkEntry     = AnscQueuePopEntry(pQueue);

		if( pObj != NULL)
		{
			CcspUtilCleanMibMapping(pObj);

			AnscFreeMemory(pObj);
		}
    }
}

/**********************************************************************

    prototype:

		void
		CcspUtilCleanIndexMapQueue
			(
				PQUEUE_HEADER               pQueue
			);

    description:

        This function is called to clean the Index Map Queue;

    argument:   PQUEUE_HEADER               pQueue
	            The pointer of the queue;

	return:     None

**********************************************************************/
void
CcspUtilCleanIndexMapQueue
    (
        PQUEUE_HEADER               pQueue
    )
{
    PSINGLE_LINK_ENTRY              pSLinkEntry  = (PSINGLE_LINK_ENTRY)NULL;
	PCCSP_INDEX_MAPPING   		    pObj         = (PCCSP_INDEX_MAPPING)NULL;

    pSLinkEntry = AnscQueuePopEntry(pQueue);

    while ( pSLinkEntry )
    {
        pObj            = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);
        pSLinkEntry     = AnscQueuePopEntry(pQueue);

		if( pObj != NULL)
		{
			CcspUtilCleanIndexMapping(pObj);

			AnscFreeMemory(pObj);
		}
    }
}

/**********************************************************************

    prototype:

		void
		CcspUtilCleanMibMapping
			(
				PCCSP_MIB_MAPPING   		pMapping
			);

    description:

        This function is called to clean the Mib mapping;

    argument:   PCCSP_MIB_MAPPING   		pMapping
	            The DM Mapping Info

	return:     None

**********************************************************************/
void
CcspUtilCleanMibMapping
    (
        PCCSP_MIB_MAPPING			pMapping
    )
{
    PSINGLE_LINK_ENTRY              pSLinkEntry  = (PSINGLE_LINK_ENTRY)NULL;
	PCCSP_INT_STRING_MAP			pMap         = (PCCSP_INT_STRING_MAP)NULL;

	if( pMapping->bHasMapping)
	{
		pSLinkEntry = AnscQueuePopEntry(&pMapping->MapQueue);

		while ( pSLinkEntry )
		{
			pMap            = ACCESS_CCSP_INS_STRING_MAP(pSLinkEntry);
			pSLinkEntry     = AnscQueuePopEntry(&pMapping->MapQueue);

			if( pMap != NULL)
			{
				CcspMibFreeIntStringMaping(pMap);
			}
		}
	}
}


/**********************************************************************

    prototype:

		void
		CcspUtilCleanIndexMapping
			(
				PCCSP_INDEX_MAPPING			pMapping
			);

    description:

        This function is called to clean the Index Mapping Object;

    argument:   PCCSP_INDEX_MAPPING			pMapping
	            The Index Mapping Object;

	return:     None

**********************************************************************/
void
CcspUtilCleanIndexMapping
    (
        PCCSP_INDEX_MAPPING  		pMapping
    )
{
    PSINGLE_LINK_ENTRY              pSLinkEntry  = (PSINGLE_LINK_ENTRY)NULL;
	PCCSP_INS_NUMBER_MAP			pMap         = (PCCSP_INS_NUMBER_MAP)NULL;
	PCCSP_INT_STRING_MAP			pMapp        = (PCCSP_INT_STRING_MAP)NULL;

	if( pMapping->uMapType == CCSP_MIB_MAP_TO_INSNUMBER)
	{
		pSLinkEntry = AnscQueuePopEntry(&pMapping->IndexQueue);

		while ( pSLinkEntry )
		{
			pMap            = ACCESS_CCSP_INS_NUMBER_MAP(pSLinkEntry);
			pSLinkEntry     = AnscQueuePopEntry(&pMapping->IndexQueue);

			if( pMap != NULL)
			{
				AnscFreeMemory(pMap);
			}
		}
	}
	else if( pMapping->uMapType == CCSP_MIB_MAP_TO_DM)
	{
		pSLinkEntry = AnscQueuePopEntry(&pMapping->IndexQueue);

		while ( pSLinkEntry )
		{
			pMapp            = ACCESS_CCSP_INS_STRING_MAP(pSLinkEntry);
			pSLinkEntry     = AnscQueuePopEntry(&pMapping->IndexQueue);

			if( pMapp != NULL)
			{
				CcspMibFreeIntStringMaping(pMapp);
			}
		}
	}

}

/**********************************************************************

    prototype:

		BOOL
		CcspUtilParseOidValueString
			(
				char*						pOidString,
				oid*                        pArray,
				PULONG						pSize
			);

    description:

        This function is called to parse an OID string to a OID array.

    argument:   char*						pOidString,
				The input OID value string. For instance "1,3,6,1,4,1"

				oid*                        pArray,
				The OID value array;

				PULONG						pSize
				The output buffer of length of OID;

	return:     Success or failure

**********************************************************************/
BOOL
CcspUtilParseOidValueString
	(
		char*						pOidString,
		oid*                        pArray,
		PULONG						pSize
	)
{
    PANSC_TOKEN_CHAIN               pTokenChainEnums = NULL;
    PANSC_STRING_TOKEN              pTokenEnumCode   = NULL;
    ULONG                           ulTokenCount     = 0;
    ULONG                           ulCharOffset     = 0;
    ULONG                           i                = 0;
	ULONG							uSize            = 0;

	*pSize = 0;

    /*
     *
     * A typical oid string:
     *
     *      1,3,6,1,4491
     */
    pTokenChainEnums = (PANSC_TOKEN_CHAIN)
        AnscTcAllocate
            (
                pOidString,
                ",."
            );

    if ( !pTokenChainEnums )
    {
        return  FALSE;
    }
    else
    {
        ulTokenCount = AnscTcGetTokenCount(pTokenChainEnums);
    }

    for ( i = 0; i < ulTokenCount; i++ )
    {
        ulCharOffset     = 0;
        pTokenEnumCode   = AnscTcUnlinkToken(pTokenChainEnums);
        /* CID: 52963 Dereference null return value*/
        if (!pTokenEnumCode)
                return FALSE;

		pArray[uSize] = _ansc_atoi(pTokenEnumCode->Name);
		uSize ++;

        AnscFreeMemory(pTokenEnumCode  );
    }

    if ( pTokenChainEnums )
    {
        AnscTcFree((ANSC_HANDLE)pTokenChainEnums);
    }

	*pSize = uSize;

	return TRUE;
}

/**********************************************************************

    prototype:

		ULONG
		CcspUtilTR69StringToDataType
			(
				char*						pBuffer
			);

    description:

        This function is called to parse the TR69 data type string to an integer.

    argument:   char*						pBuffer,
				The input TR69 data type string

	return:     The integer data type value

**********************************************************************/
ULONG
CcspUtilTR69StringToDataType
    (
        char*						pBuffer
    )
{
	if( AnscEqualString(pBuffer, CCSP_TR69_STR_DataType_int, TRUE))
	{
		return CCSP_TR69_DataType_int;
	}
	else if( AnscEqualString(pBuffer, CCSP_TR69_STR_DataType_unsignedInt, TRUE))
	{
		return CCSP_TR69_DataType_unsignedInt;
	} 
	else if( AnscEqualString(pBuffer, CCSP_TR69_STR_DataType_boolean, TRUE))
	{
		return CCSP_TR69_DataType_boolean;
	} 
	else if( AnscEqualString(pBuffer, CCSP_TR69_STR_DataType_dateTime, TRUE))
	{
		return CCSP_TR69_DataType_dateTime;
	} 
	else if( AnscEqualString(pBuffer, CCSP_TR69_STR_DataType_base64, TRUE))
	{
		return CCSP_TR69_DataType_base64;
	} 
	else if( AnscEqualString(pBuffer, CCSP_TR69_STR_DataType_string, TRUE))
	{
		return CCSP_TR69_DataType_string;
	} 

	AnscTraceWarning(("Unknown TR69 data type - %s | string will be used instead. \n", pBuffer));

	return CCSP_TR69_DataType_string;
}

/**********************************************************************

    prototype:

		ULONG
		CcspUtilMIBStringToDataType
			(
				char*						pBuffer
			);

    description:

        This function is called to parse the MIB dataType string.

    argument:   char*						pBuffer,
				The input MIB data type string

	return:     The integer data type value

**********************************************************************/
ULONG
CcspUtilMIBStringToDataType
    (
        char*						pBuffer
    )
{
	/* it's replaced by "checkMibDataType" */
	return 0;
}

/**********************************************************************

    prototype:

		void
		CcspUtilTR69DataTypeToString
			(
				ULONG						uDataType,
				char*						pBuffer
			);

    description:

        This function is called to get TR69 data type string based on the data type value;

    argument:   ULONG						uDataType,
				The input TR69 data type value;

				char*						pBuffer,
				The output buffer will have data type string copied.

	return:     None

**********************************************************************/
void
CcspUtilTR69DataTypeToString
    (
		ULONG						uDataType,
        char*						pBuffer
    )
{
	/* we don't need it for now */
}

/**********************************************************************

    prototype:

		BOOL
		CcspUtilLoadMibInfo
			(
				PCCSP_MIB_INFO				pInfo,
				PQUEUE_HEADER               pQueue,
				ANSC_HANDLE					hXmlHandle
			);

    description:

        This function is called to load MIB infor from XML.

    argument:   
				PCCSP_MIB_INFO				pInfo,
				The input of MIB infor handle;

				PQUEUE_HEADER               pQueue,
				The queue;

				ANSC_HANDLE					hXmlHandle
				The input XML handle;

	return:     Success or failure

**********************************************************************/
void
checkMibDataType
	(
		char*						pType,
		PCCSP_MIB_INFO				pInfo,
		PQUEUE_HEADER               pQueue
	)
{
	pInfo->bIsRowStatus = FALSE;

	if( AnscEqualString(pType, "Boolean", FALSE))
	{
		pInfo->uType = ASN_BOOLEAN;
	}
	else if( AnscEqualString(pType, "INTEGER", FALSE) || AnscEqualString(pType, "Integer32", TRUE) ||
		AnscEqualString(pType, "TimeInterval", FALSE) || AnscEqualString(pType, "Timeout", FALSE) ||
		AnscEqualString(pType, "TestAndIncr", TRUE)   || AnscEqualString(pType, "InterfaceIndexOrZero", TRUE)||
		AnscEqualString(pType, "InterfaceIndex", TRUE))
	{
		pInfo->uType = ASN_INTEGER;
	}
	else if( AnscEqualString(pType, "TruthValue", FALSE))
	{
		pInfo->uType = ASN_INTEGER;
		pInfo->uMaskLimit = CCSP_MIB_LIMIT_BOTH;
		pInfo->nMin       = 1;
		pInfo->nMax		  = 2;
	}
	else if( AnscEqualString(pType, "Counter32", TRUE))
	{
		pInfo->uType = ASN_COUNTER;
	}
	else if( AnscEqualString(pType, "Opaque", TRUE))
	{
		pInfo->uType = ASN_OPAQUE;
	}
	else if( AnscEqualString(pType, "Gauge32", TRUE) || AnscEqualString(pType, "Unsigned32", FALSE)||
		AnscEqualString(pType, "InetZoneIndex", TRUE) ||AnscEqualString(pType, "Unsigned", TRUE) )
	{
		pInfo->uType        = ASN_UNSIGNED;
	}
	else if( AnscEqualString(pType, "RowStatus", TRUE))
	{
		pInfo->uType = ASN_INTEGER;

		if( pInfo->uMaskLimit == CCSP_MIB_NO_LIMIT)
		{
			pInfo->uMaskLimit = CCSP_MIB_LIMIT_BOTH;
			pInfo->nMin       = 1;
			pInfo->nMax		  = 6;
		}

		pInfo->bIsRowStatus = TRUE;
	}
	else if( AnscEqualString(pType, "InetPortNumber", TRUE))
	{
		pInfo->uType = ASN_UNSIGNED;

		if( pInfo->uMaskLimit == CCSP_MIB_NO_LIMIT)
		{
			pInfo->uMaskLimit = CCSP_MIB_LIMIT_BOTH;
			pInfo->nMin       = 0;
			pInfo->nMax		  = 65535;
		}
	}
	else if( AnscEqualString(pType, "BitField", FALSE)||
		AnscEqualString(pType, "BitString", TRUE))
	{
		pInfo->uType = ASN_BIT_STR;
	}
	else if ( AnscEqualString(pType, "BITS", FALSE))
	{
		pInfo->uType = ASN_OCTET_STR;
	}
	else if( AnscEqualString(pType, "SaRgUserChangedFlag", FALSE))
	{
		pInfo->uType = ASN_OCTET_STR;
		CcspUtilParseEnumString("lanParameters(0),wanMTU(1),wirelessBasic(2),wirelessAdvanced(3),wirelessSecurity(4),\
wirelessAccessControl(5),fixedCPE(6),ipAddrFiltering(7),macAddrFiltering(8),portFiltering(9),portForwarding(10),\
portTriggers(11),dmzHost(12),blockProxy(13),blockCookies(14),blockJava(15),blockActiveX(16),blockPopup(17),\
blockFragments(18),detectPortScan(19),detectFlood(20),firewallEvent(21)", pQueue);
	}
	else if( AnscEqualString(pType, "IpAddress", FALSE))
	{
		pInfo->uType = ASN_IPADDRESS;
	}
	else if( AnscEqualString(pType, "DisplayString", TRUE) ||AnscEqualString(pType, "SnmpAdminString", TRUE)||
		     AnscEqualString(pType, "OwnerString", TRUE) ||AnscEqualString(pType, "InetAddress", TRUE))
	{
		pInfo->uType = ASN_OCTET_STR;
		if( pInfo->uMaskLimit == CCSP_MIB_NO_LIMIT)
		{
			pInfo->uMaskLimit = CCSP_MIB_LIMIT_BOTH;
			pInfo->nMin       = 0;
			pInfo->nMax		  = 255;
		}
	}
	else if( AnscEqualString(pType, "TimeTicks", FALSE) || AnscEqualString(pType, "TimeStamp", FALSE))
	{
		pInfo->uType = ASN_TIMETICKS;
	}
	else if( AnscEqualString(pType, "InetAddressType", TRUE))
	{
		pInfo->uType = ASN_INTEGER;
		if( pInfo->uMaskLimit == CCSP_MIB_NO_LIMIT)
		{
			pInfo->uMaskLimit = CCSP_MIB_LIMIT_BOTH;
			pInfo->nMin       = 0;
			pInfo->nMax		  = 16;
		}

		CcspUtilParseEnumString("unknown(0),ipv4(1),ipv6(2),ipv4z(3),ipv6z(4),dns(16)", pQueue);
	}
	else if( AnscEqualString(pType, "TransportAddressType", TRUE))
	{
		pInfo->uType = ASN_INTEGER;
		if( pInfo->uMaskLimit == CCSP_MIB_NO_LIMIT)
		{
			pInfo->uMaskLimit = CCSP_MIB_LIMIT_BOTH;
			pInfo->nMin       = 0;
			pInfo->nMax		  = 16;
		}

		CcspUtilParseEnumString("unknown(0),udpIpv4(1),udpIpv6(2),udpIpv4z(3),udpIpv6z(4),tcpIpv4(5),tcpIpv6(6),tcpIpv4z(7),tcpIpv6z(8),sctpIpv4(9),sctpIpv6(10),\
sctpIpv4z(11),sctpIpv6z(12),local(13),udpDns(14),tcpDns(15),sctpDns(16)", pQueue);
	}
	else if( AnscEqualString(pType, "InetVersion", TRUE))
	{
		pInfo->uType = ASN_INTEGER;
		if( pInfo->uMaskLimit == CCSP_MIB_NO_LIMIT)
		{
			pInfo->uMaskLimit = CCSP_MIB_LIMIT_BOTH;
			pInfo->nMin       = 0;
			pInfo->nMax		  = 2;
		}

		CcspUtilParseEnumString("unknown(0),ipv4(1),ipv6(2)", pQueue);
	}
	else if( AnscEqualString(pType,"Counter64", FALSE)||AnscEqualString(pType,"CounterBasedGauge64", FALSE) ||
		AnscEqualString(pType,"ZeroBasedCounter64", FALSE))
	{
		pInfo->uType = ASN_COUNTER64;
	}
	else if( AnscEqualString(pType, "OCTET STRING", FALSE))
	{
		pInfo->uType = ASN_OCTET_STR;
	}
	else if( AnscEqualString(pType, "MacAddress", FALSE) || AnscEqualString(pType, "PhysAddress", FALSE))
	{
		pInfo->uType = ASN_OCTET_STR;
		pInfo->uMaskLimit = CCSP_MIB_LIMIT_BOTH;
		pInfo->nMin       = 6;
		pInfo->nMax		  = 6;
	}
	else if( AnscEqualString(pType, "DateAndTime", FALSE))
	{
		pInfo->uType = ASN_OCTET_STR;
		pInfo->uMaskLimit = CCSP_MIB_LIMIT_BOTH;
		pInfo->nMin       = 8;
		pInfo->nMax		  = 11;
	}
	else
	{
		AnscTraceWarning(("Unknown MIB data type: %s, treat it as an OCTET_STRING.\n", pType));

		pInfo->uType = ASN_OCTET_STR;
	}

}


BOOL
CcspUtilLoadMibInfo
	(
		PCCSP_MIB_INFO				pInfo,
		PQUEUE_HEADER               pQueue,
		ANSC_HANDLE					hXmlHandle
	)
{
    PANSC_XML_DOM_NODE_OBJECT       pRootNode          = (PANSC_XML_DOM_NODE_OBJECT)hXmlHandle;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode         = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode2        = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode3        = (PANSC_XML_DOM_NODE_OBJECT)NULL;
	char							buffer[256]        = { 0 };
	ULONG							uSize              = 256;

	/* load the lastOid */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_MibInfo_lastOid);

	if( pChildNode == NULL)
	{
		AnscTraceError(("'lastOid' is not configure, failed to load the MIB Info.\n"));
		return FALSE;
	}

	pChildNode->GetDataUlong(pChildNode, NULL, &pInfo->uLastOid);

	/* ingore "name" */

	/* get access */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_MibInfo_access);

	if( pChildNode != NULL)
	{
		pChildNode->GetDataString(pChildNode, NULL, buffer, &uSize);
	}

	if( AnscEqualString(buffer, "ReadWrite", TRUE) || AnscEqualString(buffer, "WriteOnly", TRUE))
	{
		pInfo->bWritable = TRUE;
	}
	else
	{
		pInfo->bWritable = FALSE;
	}

	/* get the dataType */
	AnscZeroMemory(buffer, 256);
	uSize = 255;
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_MibInfo_dataType);

	if( pChildNode == NULL)
	{
		AnscTraceError(("'dataType' is not configured for lastOid = %lu\n", pInfo->uLastOid));

		return FALSE;
	}

	pChildNode->GetDataString(pChildNode, NULL, buffer, &uSize);

	/* get the range */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_MibInfo_range);
	pInfo->uMaskLimit = CCSP_MIB_NO_LIMIT;

	if( pChildNode != NULL)
	{
		pChildNode2 = (PANSC_XML_DOM_NODE_OBJECT)pChildNode->GetChildByName(pChildNode, CCSP_XML_MibInfo_min);
		pChildNode3 = (PANSC_XML_DOM_NODE_OBJECT)pChildNode->GetChildByName(pChildNode, CCSP_XML_MibInfo_max);		

		if( pChildNode2 != NULL)
		{
			if( AnscEqualString(buffer, "INTEGER", FALSE) || AnscEqualString(buffer, "Integer32", TRUE) )
			{
				pChildNode2->GetDataLong(pChildNode2, NULL, (LONG*)&pInfo->nMin);
			}
			else
			{				
				pChildNode2->GetDataUlong(pChildNode2, NULL, (ULONG*)&pInfo->nMin);
			}
			
			if( pChildNode3 != NULL)
			{
				if( AnscEqualString(buffer, "INTEGER", FALSE) || AnscEqualString(buffer, "Integer32", TRUE) )
				{
					pChildNode3->GetDataLong(pChildNode3, NULL, (LONG*)&pInfo->nMax);
				}
				else
				{				
					pChildNode3->GetDataUlong(pChildNode3, NULL, (ULONG*)&pInfo->nMax);
				}
			
				pInfo->uMaskLimit = CCSP_MIB_LIMIT_BOTH;
			}
			else
			{
				pInfo->uMaskLimit = CCSP_MIB_LIMIT_MIN;
			}
		}
		else if( pChildNode3 != NULL)
		{
			if( AnscEqualString(buffer, "INTEGER", FALSE) || AnscEqualString(buffer, "Integer32", TRUE) )
			{
				pChildNode3->GetDataLong(pChildNode3, NULL, (ULONG*)&pInfo->nMax);
			}
			else
			{				
				pChildNode3->GetDataUlong(pChildNode3, NULL, (ULONG*)&pInfo->nMax);
			}
		
			pInfo->uMaskLimit = CCSP_MIB_LIMIT_MAX;
		}
	}

	/* check the MIB data type limitations */
	checkMibDataType(buffer, pInfo, pQueue);
	AnscCopyString(pInfo->pType, buffer);

	return TRUE;
}


/**********************************************************************

    prototype:

		BOOL
		CcspUtilLoadDMMappingInfo
			(
				PCCSP_DM_MAPPING_INFO    	pInfo,
				PQUEUE_HEADER               pQueue,
				ANSC_HANDLE					hXmlHandle
			);

    description:

        This function is called to load DM Mapping infor from XML.

    argument:   
				PCCSP_DM_MAPPING_INFO		pInfo,
				The input of MIB infor handle;

				PQUEUE_HEADER               pQueue,
				The enum queue;

				ANSC_HANDLE					hXmlHandle
				The input XML handle;

	return:     Success or failure

**********************************************************************/
BOOL
CcspUtilLoadDMMappingInfo
	(
		PCCSP_DM_MAPPING_INFO   	pInfo,
		PQUEUE_HEADER               pQueue,
		ANSC_HANDLE					hXmlHandle
	)
{
    PANSC_XML_DOM_NODE_OBJECT       pRootNode          = (PANSC_XML_DOM_NODE_OBJECT)hXmlHandle;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode         = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode2        = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode3        = (PANSC_XML_DOM_NODE_OBJECT)NULL;
	char							buffer[256]        = { 0 };
	ULONG							uSize              = MAXI_DM_NAME_LENGTH;

	/* get the name */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_DMInfo_paramName);

	if( pChildNode == NULL)
	{
		AnscTraceError(("'paramName' is not configured in DMInfo.\n"));

		return FALSE;
	}

	pChildNode->GetDataString(pChildNode, NULL, pInfo->pDMName, &uSize);

	/* get rid of the '%d' at the end */
	if( pInfo->pDMName[uSize - 2] == '%' && pInfo->pDMName[uSize - 1] == 'd')
	{
		pInfo->pDMName[uSize - 2] = 0;
		pInfo->pDMName[uSize - 1] = 0;
	}

	/* get the type */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_DMInfo_dataType);

	if( pChildNode == NULL)
	{
		AnscTraceError(("TR69 'dataType' is not configured in DMInfo.\n"));

		return FALSE;
	}

	uSize = MAXI_DM_NAME_LENGTH;
	pChildNode->GetDataString(pChildNode, NULL, buffer, &uSize);

	pInfo->uDataType = CcspUtilTR69StringToDataType(buffer);

	/* check extra */
	uSize = 256;
	AnscZeroMemory(buffer, uSize);
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_DMInfo_enumeration);

	if( pChildNode == NULL)
	{
		pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_DMInfo_bitmask);
	}

	if( pChildNode != NULL)
	{
		pChildNode->GetDataString(pChildNode, NULL, buffer, &uSize);

		AnscTraceInfo(("ExtraInfo in DMMapping loaded:\n%s\n", buffer));

		/* parse extra to map queue */
		CcspUtilParseEnumString(buffer, pQueue);
	}

	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_DMInfo_background);
	if (pChildNode) {
		pInfo->backgroundCommit = 1;
	} else {
		pInfo->backgroundCommit = 0;
	}

	return TRUE;
}

/**********************************************************************

    prototype:

		BOOL
		CcspUtilLoadIndexMappingInfo
			(
				PCCSP_INDEX_MAPPING_INFO  	pInfo,
				PQUEUE_HEADER               pQueue,
				ANSC_HANDLE					hXmlHandle
			);

    description:

        This function is called to load Index Mapping infor from XML.

    argument:   
				PCCSP_INDEX_MAPPING_INFO	pInfo,
				The input of Index Mapping info

				PQUEUE_HEADER               pQueue,
				The index queue;

				ANSC_HANDLE					hXmlHandle
				The input XML handle;

	return:     Success or failure

**********************************************************************/
BOOL
CcspUtilLoadIndexMappingInfo
	(
		PCCSP_INDEX_MAPPING_INFO   	pInfo,
		PQUEUE_HEADER               pQueue,
		ANSC_HANDLE					hXmlHandle
	)
{
    PANSC_XML_DOM_NODE_OBJECT       pRootNode          = (PANSC_XML_DOM_NODE_OBJECT)hXmlHandle;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode         = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode2        = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode3        = (PANSC_XML_DOM_NODE_OBJECT)NULL;
	char							buffer[256]        = { 0 };
	ULONG							uSize              = MAXI_DM_NAME_LENGTH;
	PCCSP_INS_NUMBER_MAP			pNewMap            = (PCCSP_INS_NUMBER_MAP)NULL;
	ULONG							uFrom              = 0;
	ULONG							uTo                = 0;

	/* get the mapped TR Table Obj name */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_IndexInfo_tableObj);

	if( pChildNode == NULL)
	{
		AnscTraceError(("The mapped TR Table object is not configured.Failed to load IndexMapping.\n"));

		return FALSE;
	}

	pChildNode->GetDataString(pChildNode, NULL, pInfo->pTableObj, &uSize);

	/* get rid of the '%d' at the end */
	if( pInfo->pTableObj[uSize - 2] == '%' && pInfo->pTableObj[uSize - 1] == 'd')
	{
		pInfo->pTableObj[uSize - 2] = 0;
		pInfo->pTableObj[uSize - 1] = 0;
	}


	/* check the mapping array if exists */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_IndexInfo_map);

	while(pChildNode != NULL)
	{
		uFrom = 0;
		uTo   = 0;

		pChildNode2 = (PANSC_XML_DOM_NODE_OBJECT)pChildNode->GetChildByName(pChildNode, CCSP_XML_IndexInfo_from);
		pChildNode3 = (PANSC_XML_DOM_NODE_OBJECT)pChildNode->GetChildByName(pChildNode, CCSP_XML_IndexInfo_to);

		if( pChildNode2 && pChildNode3)
		{
			pChildNode2->GetDataUlong(pChildNode2, NULL,&uFrom);
			pChildNode3->GetDataUlong(pChildNode3, NULL, &uTo);

			pNewMap = (PCCSP_INS_NUMBER_MAP)AnscAllocateMemory(sizeof(CCSP_INS_NUMBER_MAP));

			if( pNewMap != NULL)
			{
				pNewMap->uMibValue = uFrom;
				pNewMap->uDMValue  = uTo;

				AnscQueuePushEntry(pQueue, &pNewMap->Linkage);
			}
		}
		else
		{
			AnscTraceWarning(("Either 'from' or 'to' is not configured in the index mapping.\n"));
		}

		/* get next */
		pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetNextChild(pRootNode, pChildNode);
	}

	return TRUE;
}


/**********************************************************************

    prototype:

		BOOL
		CcspUtilLoadSubDMIndexMappingInfo
			(
				PCCSP_INDEX_MAPPING_INFO  	pInfo,
				PQUEUE_HEADER               pQueue,
				ANSC_HANDLE					hXmlHandle
			);

    description:

        This function is called to load Index Mapping using a member DM from XML.

    argument:   
				PCCSP_INDEX_MAPPING_INFO	pInfo,
				The input of Index Mapping info

				PQUEUE_HEADER               pQueue,
				The index queue;

				ANSC_HANDLE					hXmlHandle
				The input XML handle;

	return:     Success or failure

**********************************************************************/
BOOL
CcspUtilLoadSubDMIndexMappingInfo
	(
		PCCSP_SUBDM_INDEX_MAPPING_INFO   	pInfo,
		PQUEUE_HEADER                       pQueue,
		ANSC_HANDLE					        hXmlHandle
	)
{
    PANSC_XML_DOM_NODE_OBJECT       pRootNode          = (PANSC_XML_DOM_NODE_OBJECT)hXmlHandle;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode         = (PANSC_XML_DOM_NODE_OBJECT)NULL;
	char							buffer[256]        = { 0 };
	ULONG							uSize              = MAXI_DM_NAME_LENGTH;

	/* get the mapped TR Table Obj name */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_IndexInfo_tableObj);

	if( pChildNode == NULL)
	{
		AnscTraceError(("The mapped TR Table object is not configured.Failed to load IndexMapping.\n"));

		return FALSE;
	}

	pChildNode->GetDataString(pChildNode, NULL, pInfo->pTableObj, &uSize);

	/* get rid of the '%d' at the end */
	if( pInfo->pTableObj[uSize - 2] == '%' && pInfo->pTableObj[uSize - 1] == 'd')
	{
		pInfo->pTableObj[uSize - 2] = 0;
		pInfo->pTableObj[uSize - 1] = 0;
	}

        /* get the mapped TR Sub Obj name */
	uSize = MAXI_DM_NAME_LENGTH;
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_IndexInfo_subDm);

	if( pChildNode == NULL)
	{
		AnscTraceError(("The mapped TR sub object is not configured.Failed to load IndexMapping.\n"));

		return FALSE;
	}

	pChildNode->GetDataString(pChildNode, NULL, pInfo->pSubDMName, &uSize);
	
	return TRUE;
}

/**********************************************************************

    prototype:

		PCCSP_MIB_MAPPING
		CcspUtilLoadMibMappingInfo
			(
				ANSC_HANDLE					hXmlHandle
			);

    description:

        This function is called to load a MIB mapping info from XML.

    argument:   
				ANSC_HANDLE					hXmlHandle
				The input XML handle;

	return:     The MIB Mapping Info object

**********************************************************************/
PCCSP_MIB_MAPPING
CcspUtilLoadMibMappingInfo
	(
		ANSC_HANDLE					hXmlHandle
	)
{
    PANSC_XML_DOM_NODE_OBJECT       pRootNode          = (PANSC_XML_DOM_NODE_OBJECT)hXmlHandle;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode         = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PCCSP_MIB_MAPPING				pMibMapping        = (PCCSP_MIB_MAPPING)NULL;

	/* get 'mib' node */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_MibMap_mib);

	if( pChildNode == NULL)
	{
		AnscTraceWarning(("No 'mib' is configure in the 'map'.\n"));

		return NULL;
	}

	pMibMapping = (PCCSP_MIB_MAPPING)AnscAllocateMemory(sizeof(CCSP_MIB_MAPPING));

	if( pMibMapping == NULL)
	{
		return NULL;
	}

	/* init the queue */
	AnscQueueInitializeHeader(&pMibMapping->MapQueue);

	/* load the Mib Info */
	CcspUtilLoadMibInfo(&pMibMapping->MibInfo, &pMibMapping->MapQueue, (ANSC_HANDLE)pChildNode);

	/* get dm info */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_MibMap_dm);

	if( pChildNode == NULL)
	{
		pMibMapping->bHasMapping = FALSE;
	}
	else
	{
		pMibMapping->bHasMapping = TRUE;
		CcspUtilLoadDMMappingInfo(&pMibMapping->Mapping, &pMibMapping->MapQueue, (ANSC_HANDLE)pChildNode);		 
	}

	return pMibMapping;
}


/**********************************************************************

    prototype:

		PCCSP_INDEX_MAPPING
		CcspUtilLoadIndexMapping
			(
				ANSC_HANDLE					hXmlHandle
			);

    description:

        This function is called to load an Index mapping from XML.

    argument:   
				ANSC_HANDLE					hXmlHandle
				The input XML handle;

	return:     The Index Mapping Info object

**********************************************************************/
PCCSP_INDEX_MAPPING
CcspUtilLoadIndexMapping
	(
		ANSC_HANDLE					hXmlHandle
	)
{
    PANSC_XML_DOM_NODE_OBJECT       pRootNode          = (PANSC_XML_DOM_NODE_OBJECT)hXmlHandle;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode         = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode2        = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode3        = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PCCSP_INDEX_MAPPING      		pIndexMapping      = (PCCSP_INDEX_MAPPING)NULL;

	/* get 'mib' node */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_IndexMap_mib);

	if( pChildNode == NULL)
	{
		AnscTraceWarning(("No 'mib' is configure in the index map.\n"));

		return NULL;
	}

	pIndexMapping = (PCCSP_INDEX_MAPPING)AnscAllocateMemory(sizeof(CCSP_INDEX_MAPPING));

	if( pIndexMapping == NULL)
	{
		return NULL;
	}

    /* init the queues */
	AnscQueueInitializeHeader(&pIndexMapping->IndexQueue);

	/* load the Mib Info */
	CcspUtilLoadMibInfo(&pIndexMapping->MibInfo, NULL, (ANSC_HANDLE)pChildNode);

	/* get map info */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_IndexMap_mapToInsNumber);
	pChildNode2 = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_IndexMap_dm);
	pChildNode3 = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_IndexMap_subDm);

	if( pChildNode != NULL)
	{
		pIndexMapping->uMapType = CCSP_MIB_MAP_TO_INSNUMBER;
		CcspUtilLoadIndexMappingInfo(&pIndexMapping->Mapping.IndexMappingInfo, &pIndexMapping->IndexQueue, (ANSC_HANDLE)pChildNode);		 
	}
	else if( pChildNode2 != NULL)
	{
		pIndexMapping->uMapType = CCSP_MIB_MAP_TO_DM;
		CcspUtilLoadDMMappingInfo(&pIndexMapping->Mapping.DMMappingInfo,NULL, (ANSC_HANDLE)pChildNode2);		 
	}
	else if( pChildNode3 != NULL) 
	{
		pIndexMapping->uMapType = CCSP_MIB_MAP_TO_SUBDM;
                CcspUtilLoadSubDMIndexMappingInfo(&pIndexMapping->Mapping.SubDMMappingInfo, NULL, (ANSC_HANDLE)pChildNode3);
	}
	else
	{
		pIndexMapping->uMapType = CCSP_MIB_NO_MAPPING;

		AnscTraceWarning(("There's no mapping configured for the index map.Warning!\n"));
	}

	return pIndexMapping;

}

/**********************************************************************

    prototype:

		BOOL
		CcspUtilParseEnumString
			(
				char*						pEnumString,
				PQUEUE_HEADER               pQueue
			);

    description:

        This function is called to parse Enumeration/Bitmask string

    argument:   
				char*						pEnumString,
				The input Enumeration/Bitmask string;

				PQUEUE_HEADER               pQueue
				The pointer of the map queue;

	return:     Success or failure

**********************************************************************/
BOOL
CcspUtilParseEnumString
	(
		char*						pEnumString,
		PQUEUE_HEADER               pQueue
    )
{
	PCCSP_INT_STRING_MAP			pMap   = (PCCSP_INT_STRING_MAP)NULL;
	char*							pTemp  = pEnumString;
	ULONG							ulSize = 0;
    PANSC_TOKEN_CHAIN               pTokenChainEnums = NULL;
    PANSC_STRING_TOKEN              pTokenEnumString = NULL;
    PANSC_STRING_TOKEN              pTokenEnumCode   = NULL;
    ULONG                           ulTokenCount     = 0;
    ULONG                           ulCharOffset     = 0;
    ULONG                           i                = 0;
	char*							pTmpString       = NULL;

    /*
     *
     * A typical enumerated string should be defined like this:
     *
     *      "string: Normal(1), UseAllocatedSubnet(2), Passthrough(3)"
     */
    pTokenChainEnums = (PANSC_TOKEN_CHAIN)
        AnscTcAllocate
            (
                pEnumString,
                ";()[]{}"
            );

    if ( !pTokenChainEnums )
    {
        return  FALSE;
    }
    else
    {
        ulTokenCount = AnscTcGetTokenCount(pTokenChainEnums);
    }

    for ( i = 0; i < ulTokenCount / 2; i++ )
    {
        ulCharOffset     = 0;
        pTokenEnumString = AnscTcUnlinkToken(pTokenChainEnums);
        pTokenEnumCode   = AnscTcUnlinkToken(pTokenChainEnums);
        /* CID:57262 Dereference null return value*/
        if (!pTokenEnumString || !pTokenEnumCode)
             return FALSE;

        while ( pTokenEnumString->Name[ulCharOffset] == ' ' ||  pTokenEnumString->Name[ulCharOffset] == ',')
        {
            ulCharOffset++;
        }

		/* add the map */
		pMap = (PCCSP_INT_STRING_MAP)AnscAllocateMemory(sizeof(CCSP_INT_STRING_MAP));

		if( pMap != NULL)
		{
			pMap->EnumCode = _ansc_atoi(pTokenEnumCode->Name);
			pTmpString     = &pTokenEnumString->Name[ulCharOffset];
			pMap->pString  = AnscCloneString(pTmpString);

			/* add it to the queue */
			AnscQueuePushEntry(pQueue, &pMap->Linkage);
		}

        AnscFreeMemory(pTokenEnumString);
        AnscFreeMemory(pTokenEnumCode  );
    }

    if ( pTokenChainEnums )
    {
        AnscTcFree((ANSC_HANDLE)pTokenChainEnums);
    }

	return TRUE;
}

/**********************************************************************

    prototype:

		void
		CcspUtilTraceOid
			(
				oid*						pOid,
				ULONG						uLength
			);

    description:

        This function is called to trace an oid array.

    argument:   
				oid*						pOid,
				The input oid array;

				ULONG						uLength
				The length of the array;

	return:     None

**********************************************************************/
void
CcspUtilTraceOid
	(
		oid*						pOid,
		ULONG						uLength
	)
{
	int								i           = 0;
	char							buffer[512] = {0};
	char*							pTemp       = buffer;

	AnscCopyString(buffer, "Oid:[");
	pTemp = (char*)(buffer + AnscSizeOfString(buffer));

	for( i = 0; i < uLength; i ++)
	{
		if( i == 0)
		{
			_ansc_sprintf(pTemp, "%d", (int)pOid[i]);
		}
		else
		{
			_ansc_sprintf(pTemp, ".%d", (int)pOid[i]);
		}

		pTemp += AnscSizeOfString(pTemp);
	}

	_ansc_sprintf(pTemp, "] Len=%lu\n", uLength);

	AnscTraceInfo((buffer));
}

/**********************************************************************

    prototype:

		void
		CcspUtilInitMibValueArray
			(
				PQUEUE_HEADER				pMibObjQueue,
				PQUEUE_HEADER				pMibValueQueue
			);

    description:

        This function is called to init Mib value queue based on the information
		in Mib Object Queue;

    argument:   
				PQUEUE_HEADER				pMibObjQueue,
				The input MIB Object queue;

				PQUEUE_HEADER				pMibValueQueue
				The output MIB value queueu;

	return:     None

**********************************************************************/
void
CcspUtilInitMibValueArray
	(
		PQUEUE_HEADER				pMibObjQueue,
		PQUEUE_HEADER				pMibValueQueue
	)
{	
	PCCSP_MIB_VALUE					pMibValue			= (PCCSP_MIB_VALUE)NULL;
	PCCSP_MIB_MAPPING				pMibMap				= (PCCSP_MIB_MAPPING)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry         = (PSINGLE_LINK_ENTRY)NULL;

	if( !pMibObjQueue || !pMibValueQueue || pMibObjQueue->Depth == pMibValueQueue->Depth ||
		pMibValueQueue->Depth > 0)
	{
		return;
	}

    pSLinkEntry = AnscQueueGetFirstEntry(pMibObjQueue);

    while ( pSLinkEntry )
    {
        pMibMap         = ACCESS_CCSP_MIB_MAPPING(pSLinkEntry);
        pSLinkEntry     = AnscQueueGetNextEntry(pSLinkEntry);

		if( pMibMap != NULL)
		{
			/* create corresponding MibValue object and add it to the other queue */
			pMibValue = (PCCSP_MIB_VALUE)AnscAllocateMemory(sizeof(CCSP_MIB_VALUE));

			if( pMibValue != NULL)
			{
				pMibValue->uLastOid  = pMibMap->MibInfo.uLastOid;
				pMibValue->uType     = pMibMap->MibInfo.uType;
				pMibValue->Value.u64Value.high = 0;
				pMibValue->Value.u64Value.low = 0;
				pMibValue->BackValue.uValue   = 0;
				pMibValue->BackValue.pBuffer  = NULL;
				pMibValue->uBackSize          = 0;

				if( AnscEqualString(pMibMap->MibInfo.pType, "MacAddress", FALSE)|| AnscEqualString(pMibMap->MibInfo.pType, "PhysAddress", FALSE))
				{
					pMibValue->uSize = 6;
				}
				else if( pMibValue->uType >= ASN_IPADDRESS && pMibValue->uType <= ASN_OPAQUE)
				{
					pMibValue->uSize = sizeof(ULONG);
				}
				else if( pMibValue->uType == ASN_COUNTER64)
				{
					pMibValue->uSize = sizeof(ULONG) * 2;
				}
				else if (pMibValue->uType <= ASN_INTEGER)
				{
					pMibValue->uSize = sizeof(int);
				}
				else
				{
					pMibValue->uSize = 0;
				}

				/* push to the queue */
				AnscQueuePushEntry(pMibValueQueue, &pMibValue->Linkage);
			}
		}
    }

}


/**********************************************************************

    prototype:

		PCCSP_MIB_VALUE
		CcspUtilLookforMibValueObjWithOid
			(
				PQUEUE_HEADER				pMibValueQueue,
				oid							uLastOid
			);

    description:

        This function is called to find the Mib value object with specific oid in the queue.

    argument:   
				PQUEUE_HEADER				pMibValueQueue,
				The MIB value queue;

				oid							uLastOid
				The specified last oid value

	return:     The object if found

**********************************************************************/
PCCSP_MIB_VALUE
CcspUtilLookforMibValueObjWithOid
	(
		PQUEUE_HEADER				pMibValueQueue,
		oid							uLastOid
	)
{
	PCCSP_MIB_VALUE					pObj				= (PCCSP_MIB_VALUE)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry         = (PSINGLE_LINK_ENTRY     )NULL;
    
    pSLinkEntry = AnscQueueGetFirstEntry(pMibValueQueue);

    while ( pSLinkEntry )
    {
        pObj            = ACCESS_CCSP_MIB_VALUE(pSLinkEntry);
        pSLinkEntry     = AnscQueueGetNextEntry(pSLinkEntry);

		if( pObj != NULL && pObj->uLastOid == uLastOid)
		{
			return pObj;
		}
    }

	return NULL;

}

/**********************************************************************

    prototype:

		PCCSP_MIB_MAPPING
		CcspUtilLookforMibMapWithOid
			(
				PQUEUE_HEADER				pMibMappingQueue,
				oid							uLastOid
			);

    description:

        This function is called to find the Mib Mapping object with specific oid in the queue.

    argument:   
				PQUEUE_HEADER				pMibMappingQueue,
				The MIB value queue;

				oid							uLastOid
				The specified last oid value

	return:     The mapping object if found

**********************************************************************/
PCCSP_MIB_MAPPING
CcspUtilLookforMibMapWithOid
	(
		PQUEUE_HEADER				pMibMappingQueue,
		oid							uLastOid
	)
{
	PCCSP_MIB_MAPPING				pMibMap				= (PCCSP_MIB_MAPPING)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry         = (PSINGLE_LINK_ENTRY)NULL;
    
    pSLinkEntry = AnscQueueGetFirstEntry(pMibMappingQueue);

    while ( pSLinkEntry )
    {
        pMibMap         = ACCESS_CCSP_MIB_MAPPING(pSLinkEntry);
        pSLinkEntry     = AnscQueueGetNextEntry(pSLinkEntry);

		if( pMibMap != NULL && pMibMap->MibInfo.uLastOid == uLastOid)
		{
			return pMibMap;
		}
    }

	return NULL;

}


/**********************************************************************

    prototype:

		PCCSP_INT_STRING_MAP
		CcspUtilLookforEnumMapping
			(
				PQUEUE_HEADER				pMapping,
				ULONG						enumCode
			);

    description:

        This function is called to find Enumeration Map specified by the enum code;

    argument:   
				PQUEUE_HEADER				pMapping,
				The enumeration mapping;

				ULONG						enumCode
				The specified enum code;

	return:     The mapping object if found

**********************************************************************/
PCCSP_INT_STRING_MAP
CcspUtilLookforEnumMapping
	(
		PQUEUE_HEADER				pMapping,
		ULONG						enumCode
	)
{
	PCCSP_INT_STRING_MAP			pMap				= (PCCSP_INT_STRING_MAP)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry         = (PSINGLE_LINK_ENTRY)NULL;
    
    pSLinkEntry = AnscQueueGetFirstEntry(pMapping);

    while ( pSLinkEntry )
    {
        pMap         = ACCESS_CCSP_INS_STRING_MAP(pSLinkEntry);
        pSLinkEntry  = AnscQueueGetNextEntry(pSLinkEntry);

		if( pMap != NULL && pMap->EnumCode == enumCode)
		{
			return pMap;
		}
    }

	return NULL;

}

/**********************************************************************

    prototype:

		int
		CcspUtilLookforInsNumMapping
			(
				PQUEUE_HEADER				pMapping,
				ULONG						uValue,
				BOOL						bIsMibValue
			);

    description:

        This function is called to find index Map specified by mib value;

    argument:   
				PQUEUE_HEADER				pMapping,
				The index mapping;

				ULONG						uValue
				The specified value;

				BOOL						bIsFrom
				whether the integer value is MIB or DM insNumber

	return:     The mapping integer if found; 0 for none;

**********************************************************************/
int
CcspUtilLookforInsNumMapping
	(
		PQUEUE_HEADER				pMapping,
		ULONG						uValue,
		BOOL						bIsMibValue
	)
{
	PCCSP_INS_NUMBER_MAP			pMap				= (PCCSP_INS_NUMBER_MAP)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry         = (PSINGLE_LINK_ENTRY)NULL;
    
    pSLinkEntry = AnscQueueGetFirstEntry(pMapping);

    while ( pSLinkEntry )
    {
        pMap         = ACCESS_CCSP_INS_NUMBER_MAP(pSLinkEntry);
        pSLinkEntry  = AnscQueueGetNextEntry(pSLinkEntry);

		if( pMap != NULL)
		{
			if( bIsMibValue && pMap->uMibValue == uValue)
			{
				return pMap->uDMValue;
			}
			else if( !bIsMibValue && pMap->uDMValue == uValue)
			{
				return pMap->uMibValue;
			}
		}
    }

	return 0;
}

/**********************************************************************

    prototype:

		ULONG
		CcspUtilDMFilterToNamespace
			(
				char*						pDMFilter,
				char**						ppDestName,
				char**						ppDestPath
			);

    description:

        This function is called to get CCSP component who supports the DM filter namespace.
		For instance: If the fileter is "Device.myTable.%d.test.myType = 1", 
		It will find the component who supports "Device.myTable." and also the the instance number of "%d".

    argument:   
				char*						pDMFilter,
				The input filter string;

				char**						ppDestName,
				The output of Dest component name;

				char**						ppDestPath
				The output of Dest component path;

	return:     The instance number found.

**********************************************************************/
ULONG
CcspUtilDMFilterToNamespace
	(
		char*						pDMFilter,
		char**						ppDestName,
		char**						ppDestPath
	)
{
	char							pBuffer[256] = { 0 };
	char*							pStr         = _ansc_strstr(pDMFilter, "%d");
	char*							pTemp        = NULL;
	ULONG							insNumber    = 0;
	unsigned int*				    insArray     = NULL;
	unsigned int					insCount     = 32;
	ULONG							i			 = 0;
	ULONG							j			 = 0;
	char							pName[256]   = { 0 };
	char							pName1[256]  = { 0 };
	char							pValue[64]   = { 0 };
	int                             size		 = 0;
	parameterValStruct_t**          paramValues	 = NULL;
	char*							pReqName     = NULL;

	if( pStr == NULL)
	{
		return insNumber;
	}

	AnscCopyMemory(pBuffer, pDMFilter, (ULONG)(pStr - pDMFilter));

	if( !Cosa_FindDestComp(pBuffer, ppDestName, ppDestPath) || *ppDestName == NULL || *ppDestPath == NULL)
	{
		AnscTraceWarning(("Failed to find the CCSP component who supports '%s'\n", pBuffer));

		return insNumber;
	}

	/* get the ins count */
        /* CID: 65738 Logically dead code*/
	if( !Cosa_GetInstanceNums(*ppDestName, *ppDestPath, pBuffer, &insArray, &insCount))
	{
		return insNumber;
	}

	/* seperate the name and value  of "Device.myTable.%d.test.myType = 1" */
    pStr = _ansc_strstr(pDMFilter, "=");

	if ( !pStr)
    {
        return insNumber;
    }

	/* get name */
	pTemp = _ansc_strstr(pDMFilter, " ");

	if( pTemp != NULL && pTemp < pStr )
	{
		AnscCopyMemory(pName, pDMFilter, (ULONG)(pTemp-pDMFilter));
	}
	else
	{
		AnscCopyMemory(pName, pDMFilter, (ULONG)(pStr-pDMFilter));
	}

	/* get value */
	pStr += 1;

	/* remove the spaces at the front */
	while( pStr[0] == ' ')
	{
		pStr ++;
	}

	if( pStr[0] != '0')	AnscCopyString(pValue, pStr);

	/* remove the spaces at the end */
	pStr = _ansc_strstr(pValue, " ");

	if( pStr != NULL)
	{
		pValue[(ULONG)(pStr - pValue)] = '0';
	}

	/* check all the instances and find the first one with the type and value */
	for( i = 0; i < insNumber; i ++)
	{
		size = 0;

		_ansc_sprintf(pName1, pName, insArray[i]);

		pReqName = AnscCloneString(pName1);

		Cosa_GetParamValues(*ppDestName, *ppDestPath, &pReqName, 1, &size, &paramValues);

		if( size != 1)
		{
			CcspTraceDebug(("Cosa_GetParamValues of '%s' | size = %d\n", pReqName, size));
		}

		AnscFreeMemory(pReqName);

        CcspTraceDebug(("  %s %s\n", paramValues[0]->parameterName, paramValues[0]->parameterValue));

		if( paramValues[0] != NULL)
		{
			if( pValue[0] == '0' && ( paramValues[0]->parameterValue == NULL || AnscSizeOfString(paramValues[0]->parameterValue) == 0))
			{
				insNumber = insArray[i];
			}
			else if( AnscEqualString(pValue, paramValues[0]->parameterValue, FALSE))
			{
				insNumber = insArray[i];
			}
		}

		/* free the parameter values */
		Cosa_FreeParamValues(size, paramValues);

		if( insNumber != 0)
		{
			break;
		}
	}

EXIT:

	if( insArray)
	{
		free(insArray);
	}

	return insNumber;
}

/**********************************************************************

    prototype:

		int
		CcspUtilLookforEnumStrInMapping
			(
				PQUEUE_HEADER				pMapping,
				char*						pString
			);	

    description:

        This function is called to map a string to an integer;

    argument:   
				PQUEUE_HEADER				pMapping,
				The Ins to String mapping array;

				char*						pString
				The string;

	return:     the integer value; -1 if not found;

**********************************************************************/
int
CcspUtilLookforEnumStrInMapping
	(
		PQUEUE_HEADER				pMapping,
		char*						pString
	)
{
	PCCSP_INT_STRING_MAP			pMap				= (PCCSP_INT_STRING_MAP)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry         = (PSINGLE_LINK_ENTRY)NULL;
    
    pSLinkEntry = AnscQueueGetFirstEntry(pMapping);

    while ( pSLinkEntry )
    {
        pMap         = ACCESS_CCSP_INS_STRING_MAP(pSLinkEntry);
        pSLinkEntry  = AnscQueueGetNextEntry(pSLinkEntry);

		if( pMap != NULL && AnscEqualString(pMap->pString, pString, TRUE))
		{
			return pMap->EnumCode;
		}
    }

	AnscTraceWarning(("Unable to find the map integer value of enumeration '%s'\n", pString));

	return -1;
}

/**********************************************************************

    prototype:

		BOOL
		CcspUtilDMValueToMIB
			(
				PCCSP_MIB_MAPPING			pMibMapping,
				PCCSP_MIB_VALUE				pMibValue, 
				int							uDMType,
				char*						pValue
			);

    description:

        This function is called to copy value from DM result.

    argument:   
				PCCSP_MIB_MAPPING			pMibMapping
				The MIB mapping infor;

				PCCSP_MIB_VALUE				pMibValue, 
				The dest MIB value object;

				int							uDMType,
				The DM data type;

				char*						pValue,
				The DM string value;

	return:     success or failed

**********************************************************************/
static void
utilHexStringToBytes
	( 
		char*						pValue,
		PCCSP_MIB_VALUE				pMibValue 
	)
{
    ULONG                           ulUcharCount   = AnscSizeOfString(pValue) / 2;
    ULONG                           ulTmpValue     = 0;
    ULONG                           i              = 0;
    char                            temp_char[3];

	pMibValue->Value.puBuffer = (u_char*)AnscAllocateMemory(ulUcharCount);

    if ( !pMibValue->Value.puBuffer )
    {
        return;
    }

    for ( i = 0; i < ulUcharCount; i++ )
    {
        temp_char[0] = pValue[i*2 + 0];
        temp_char[1] = pValue[i*2 + 1];
        temp_char[2] = 0;

        ulTmpValue = AnscGetStringUlongHex(temp_char);
		pMibValue->Value.puBuffer[i] = (u_char)ulTmpValue;
    }

	pMibValue->uSize = ulUcharCount;

}

static void
utilStringToBits
	( 
		char*						pValue,
		PCCSP_MIB_VALUE				pMibValue, 
		PCCSP_MIB_MAPPING			pMibMapping
		)
{
	int                         valueArray[128] = { 0 };
	ULONG					    valueCount      = 0;
	ULONG                       i               = 0;
	char*						pTemp1          = pValue;
	char*						pTemp2          = pValue;
	int							iFind           = -1;
	int							iMax            = 0;
	char                        pTemp[256]      = { 0 };

	/* check how many bits are on */
	while( pTemp1 != NULL && AnscSizeOfString(pTemp1) > 0)
	{
		pTemp2 = _ansc_strstr(pTemp1, ",");

		if( pTemp2 != NULL)
		{
			AnscZeroMemory(pTemp, 256);
			AnscCopyMemory(pTemp, pTemp1, (ULONG)(pTemp2 - pTemp1));
		}
		else
		{
			AnscCopyString(pTemp, pTemp1);
		}

		if( AnscSizeOfString(pTemp) > 0)
		{
			iFind = CcspUtilLookforEnumStrInMapping(&pMibMapping->MapQueue, pTemp);

			if( iFind >= 0)
			{
				valueArray[valueCount] = iFind;
				valueCount ++;

				if( iFind > iMax)  iMax = iFind;
			}
			else
			{
				AnscTraceError(("No match for bit string '%s'\n", pTemp));
			}
		}

		if( pTemp2 != NULL)
		{
			pTemp1 = pTemp2 + 1;
		}
		else
		{
			break;
		}
	}

	/* allocate memory for the bits value */
	if( iMax < pMibMapping->MapQueue.Depth)
	{
		pMibValue->uSize = pMibMapping->MapQueue.Depth /8 + 1;
	}
	else
	{
		pMibValue->uSize = iMax /8 + 1;
	}

	pMibValue->Value.puBuffer = (u_char*)AnscAllocateMemory(pMibValue->uSize);

	if( pMibValue->Value.puBuffer == NULL)  return;
	
	AnscZeroMemory(pMibValue->Value.puBuffer, pMibValue->uSize);

	for( i = 0; i < valueCount; i ++)
	{
		/* turn on the corresponding bits */
		pMibValue->Value.puBuffer[pMibValue->uSize - 1 - valueArray[i]/8] |= (0x01 << valueArray[i] % 8 );
	}

}


BOOL
CcspUtilDMValueToMIB
	(
		PCCSP_MIB_MAPPING			pMibMapping,
		PCCSP_MIB_VALUE				pMibValue, 
		int							uDMType,
		char*						pValue
	)
{
	PCCSP_MIB_INFO					pMibInfo       = (PCCSP_MIB_INFO)&pMibMapping->MibInfo;
	PANSC_UNIVERSAL_TIME			pTime          = NULL;
	u_char							pBuff[8]	   = { 0 };
	SLAP_UCHAR_ARRAY*               pMacArray      = (SLAP_UCHAR_ARRAY*)NULL;

	/* free previous memory */
	if( pMibValue->uType == ASN_OCTET_STR)
	{
		if( pMibValue->Value.puBuffer != NULL && pMibValue->uSize > 0)
		{
			AnscFreeMemory(pMibValue->Value.puBuffer);

			pMibValue->Value.puBuffer = NULL;
			pMibValue->uSize          = 0;
		}
		if( pMibValue->BackValue.pBuffer != NULL)
		{
		    AnscFreeMemory(pMibValue->BackValue.pBuffer);
		    pMibValue->BackValue.pBuffer = NULL;
		}
	}
	else if( pMibValue->uType == ASN_BIT_STR)
	{
		if( pMibValue->Value.puBuffer != NULL)
		{
		    AnscFreeMemory(pMibValue->Value.puBuffer);
		    pMibValue->Value.puBuffer = NULL;
		}
		if( pMibValue->BackValue.puBuffer != NULL)
		{
		    AnscFreeMemory(pMibValue->BackValue.puBuffer);
		    pMibValue->BackValue.puBuffer = NULL;
		}
	}

	if( pMibInfo->bIsRowStatus)
	{
		if( uDMType == ccsp_boolean)
		{
			if( AnscEqualString(pValue, "true", FALSE))
			{
				pMibValue->Value.uValue = RS_ACTIVE;
			}
                        else if( AnscEqualString(pValue, "notready", FALSE))
                        {
                                pMibValue->Value.uValue = RS_NOTREADY;
                        }
			else
			{
				pMibValue->Value.uValue = RS_NOTINSERVICE;
			}
		}
		else
		{
			if( AnscEqualString(pValue, "1", FALSE))
			{
				pMibValue->Value.uValue = RS_ACTIVE;
			}
			else
			{
				pMibValue->Value.uValue = RS_NOTINSERVICE;
			}
		}
	}
	else if( uDMType == ccsp_int || uDMType == ccsp_long || uDMType == ccsp_unsignedInt || uDMType == ccsp_unsignedLong)
	{
		if( pMibValue->uType == ASN_INTEGER || (pMibValue->uType >= ASN_IPADDRESS && pMibValue->uType <= ASN_OPAQUE))
		{
			pMibValue->Value.iValue = atoi(pValue);
		}
		else if( pMibValue->uType == ASN_COUNTER64)
		{
			pMibValue->Value.u64Value.high  = 0;
			pMibValue->Value.u64Value.low   = atoi(pValue);
		}
	}
	else if ( uDMType == ccsp_boolean)
	{
		if(AnscEqualString(pMibInfo->pType, "TruthValue", FALSE))
		{
			if( AnscEqualString(pValue, "true", FALSE))
			{
				pMibValue->Value.uValue = 1;
			}
			else
			{
				pMibValue->Value.uValue = 2;
			}
		}
		else
		{
			if( AnscEqualString(pValue, "true", FALSE))
			{
				pMibValue->Value.uValue = 1;
			}
			else
			{
				pMibValue->Value.uValue = 0;
			}
		}
	}
	else if( uDMType == ccsp_string)
	{
		if( pMibValue->uType == ASN_OCTET_STR)
		{
			if( AnscEqualString(pMibInfo->pType, "MacAddress", FALSE)|| AnscEqualString(pMibInfo->pType, "PhysAddress", FALSE))
			{
				/* it's a Mac Address */
				pMacArray = SlapVcoStringToMacAddr(NULL, pValue);

				if( pMacArray != NULL)
				{
					pMibValue->uSize = pMacArray->VarCount;

					pMibValue->Value.puBuffer = (u_char*)AnscAllocateMemory(pMibValue->uSize);

					AnscCopyMemory(pMibValue->Value.puBuffer, pMacArray->Array.arrayUchar, pMibValue->uSize);

					/* free the memory */
					SlapFreeVarArray(pMacArray);
				}
				else
				{
					pMibValue->uSize = 6;
				}
			}
			else if( AnscEqualString(pMibInfo->pType, "DateAndTime", FALSE))
			{
				pTime = (PANSC_UNIVERSAL_TIME)SlapVcoStringToCalendarTime(NULL, pValue);
		
				if( pTime != NULL)
				{
					/* Mib DateAndTime Definition
					1-2 year
					3 month
					4 day
					5 hour
					6 minutes
					7 seconds
					8 deci-seconds
					*/	
					pBuff[0] = (u_char)(pTime->Year/256);
					pBuff[1] = (u_char)(pTime->Year % 256);
					pBuff[2] = (u_char)pTime->Month;
					pBuff[3] = (u_char)pTime->DayOfMonth;
					pBuff[4] = (u_char)pTime->Hour;
					pBuff[5] = (u_char)pTime->Minute;
					pBuff[6] = (u_char)pTime->Second;
					pBuff[7] = (u_char)0;

					pMibValue->Value.puBuffer = (u_char*)AnscAllocateMemory(8);
					AnscCopyMemory(pMibValue->Value.puBuffer, pBuff, 8);
					pMibValue->uSize = 8;

					/* free the memory */
					AnscFreeMemory(pTime);
				}
			}
			else if( AnscEqualString(pMibInfo->pType, "InetAddressIPv6", FALSE))
            {
                struct in6_addr *addr6;

                pMibValue->Value.puBuffer = addr6 = AnscAllocateMemory(sizeof(struct in6_addr));
                if (addr6) {
                    inet_pton(AF_INET6, pValue, addr6);
                    pMibValue->uSize = sizeof(struct in6_addr);
                }
            }
			else if( pValue != NULL)
			{
				pMibValue->Value.pBuffer = AnscCloneString(pValue);
				pMibValue->uSize         = AnscSizeOfString(pValue);
			}
			else
			{
				pMibValue->Value.pBuffer = NULL;
				pMibValue->uSize  = 0;
			}
		}
		else if( pMibValue->uType == ASN_INTEGER || pMibValue->uType == ASN_UNSIGNED)
		{
			pMibValue->Value.uValue = CcspUtilLookforEnumStrInMapping(&pMibMapping->MapQueue, pValue);

			if( pMibValue->Value.iValue < 0)
			{
				pMibValue->Value.iValue = 0;
			}
		}
		else if( pMibValue->uType == ASN_IPADDRESS)
		{
			pMibValue->Value.uValue = SlapVcoStringToIp4Addr(NULL, pValue);
			pMibValue->uSize        = 4;
		}
		else if( pMibValue->uType == ASN_BIT_STR)
		{
			/* convert it to bit string */
			if( pMibMapping->MapQueue.Depth == 0)
			{
				/* convert to bit string directly */
				utilHexStringToBytes( pValue, pMibValue);
			}
			else
			{
				utilStringToBits( pValue, pMibValue, pMibMapping);
			}
		}
	}
	else if(uDMType == ccsp_dateTime)
	{
		pTime = (PANSC_UNIVERSAL_TIME)SlapVcoStringToCalendarTime(NULL, pValue);
		
		if( pTime != NULL)
		{
			/* Mib DateAndTime Definition
			1-2 year
			3 month
			4 day
			5 hour
			6 minutes
			7 seconds
			8 deci-seconds
			*/	
			pBuff[0] = (u_char)(pTime->Year/256);
			pBuff[1] = (u_char)(pTime->Year % 256);
			pBuff[2] = (u_char)pTime->Month;
			pBuff[3] = (u_char)pTime->DayOfMonth;
			pBuff[4] = (u_char)pTime->Hour;
			pBuff[5] = (u_char)pTime->Minute;
			pBuff[6] = (u_char)pTime->Second;
			pBuff[7] = (u_char)0;

			pMibValue->Value.puBuffer = (u_char*)AnscAllocateMemory(8);
			AnscCopyMemory(pMibValue->Value.puBuffer, pBuff, 8);

			/* free the memory */
			AnscFreeMemory(pTime);
		}

		pMibValue->uSize = 8;
	}
	else
	{
		AnscTraceError(("Unsupported DM data type: %d\n", uDMType));

		return FALSE;
	}

	return TRUE;
}



/**********************************************************************

    prototype:

		BOOL
		CcspUtilMIBValueToDM
			(
				PCCSP_MIB_MAPPING			pMibMapping,
				void*						pVoid,
				netsnmp_variable_list*		pVb
			)

    description:

        This function is called to copy value MIB to DM.

    argument:   
				PCCSP_MIB_MAPPING			pMibMapping
				The MIB mapping infor;

				void*						pVoid,
				The DM value pointer;

				netsnmp_variable_list*		pVb
				The mib value pointer;

	return:     success or failed

**********************************************************************/
static char*
utilUcharArrayToString
    (
        u_char*					    pArray,
        ULONG						uLength
    )
{
    char*                           var_string   = (char*)AnscAllocateMemory(uLength * 2 + 1);
    ULONG                           i            = 0;

    if ( !var_string )
    {
        return  NULL;
    }
    else if ( !pArray || (uLength == 0) )
    {
        return  var_string;
    }
    else
    {
        for ( i = 0; i < uLength; i++ )
        {
            _ansc_sprintf
                (
                    &var_string[i * 2],
                    "%02X",
                    pArray[i]
                );
        }
    }

    return  var_string;
}

static char*
utilBitsToDMString
	(
        u_char*					    pArray,
        ULONG						uLength,
		PCCSP_MIB_MAPPING			pMibMapping
	)
{
	char							pBuffer[MAX_BUFF_SIZE]  = { 0 };
	PCCSP_INT_STRING_MAP			pStrMap        = NULL;
	ULONG							i              = 0;
	ULONG							j			   = 0;
	u_char							charByte       = 0x01;
	ULONG							uValueBit      = 0;

	for( i = 0; i < uLength; i ++)
	{
		uValueBit = 0x01;

		for( j = 0 ; j < 8; j ++ )
		{
                        /* TODO CID: 63306 Expression with no effect*/
			uValueBit << 1;

			if( pArray[i] && uValueBit)
			{
				pStrMap = CcspUtilLookforEnumMapping(&pMibMapping->MapQueue, (uLength - i - 1) * 8 + j);

				if( pStrMap != NULL)
				{
					if( pBuffer[0] != 0x00)
					{
						_ansc_strcat(pBuffer, ",");
					}

                                         /* Coverity Fix CID: 135516: STRING_OVERFLOW */
                                         if( ( strlen(pBuffer) + strlen(pStrMap->pString) ) < MAX_BUFF_SIZE) {
                                          _ansc_strcat(pBuffer, pStrMap->pString);
                                        }
                                        else
                                        {
                                            AnscTraceError(("value assigned to Buffer  exceeds the  Max Buffer value \n"));          
                                        }
				}
			}
		}

	}

	AnscTraceInfo(("Set DM Bit string value to '%s'\n", pBuffer));

	return AnscCloneString(pBuffer);
}

BOOL
CcspUtilMIBValueToDM
	(
		PCCSP_MIB_MAPPING			pMibMapping,
		void*						pVoid,
		netsnmp_variable_list*		pVb
	)
{
	char					pBuff[MAX_OCTET_BUFFER_SIZE]	= { 0 };
	ULONG					uType				= pMibMapping->MibInfo.uType;
	PCCSP_INT_STRING_MAP			pMap				= (PCCSP_INT_STRING_MAP)NULL;
	parameterValStruct_t*			pValue				= (parameterValStruct_t*)pVoid;
	ULONG					uValue				= 0;

	if( pMibMapping->MibInfo.bIsRowStatus)
	{
		uValue = *pVb->val.integer;

		if( pValue->type == ccsp_boolean)
		{
			if( uValue == RS_ACTIVE || uValue == RS_CREATEANDGO)
			{
				pValue->parameterValue = AnscCloneString("true");
			}
			else
			{
				pValue->parameterValue = AnscCloneString("false");
			}
		}
		else
		{
			if( uValue == RS_ACTIVE || uValue == RS_CREATEANDGO)
			{
				pValue->parameterValue = AnscCloneString("1");
			}
			else
			{
				pValue->parameterValue = AnscCloneString("0");
			}
		}
	}
	else if( AnscEqualString(pMibMapping->MibInfo.pType, "TruthValue", FALSE))
	{
		if( pValue->type == ccsp_boolean)
		{
			if( *pVb->val.integer == 1)
			{
				pValue->parameterValue = AnscCloneString("true");
			}
			else
			{
				pValue->parameterValue = AnscCloneString("false");
			}
		}
		else if( pValue->type == ccsp_int)
		{
			if( *pVb->val.integer == 1)
			{
				pValue->parameterValue = AnscCloneString("1");
			}
			else
			{
				pValue->parameterValue = AnscCloneString("0");
			}
		}
		else if( pValue->type == ccsp_string)
		{
			/* find the enumeration string */
			pMap = CcspUtilLookforEnumMapping(&pMibMapping->MapQueue, *pVb->val.integer);

			if( pMap != NULL)
			{
				pValue->parameterValue = AnscCloneString(pMap->pString);
			}
		}
			
	}
	else if( uType == ASN_OCTET_STR)
	{
		if( AnscEqualString(pMibMapping->MibInfo.pType, "MacAddress", FALSE) || AnscEqualString(pMibMapping->MibInfo.pType, "PhysAddress", FALSE))
		{
			_ansc_sprintf
				(
					pBuff,
					"%02X:%02X:%02X:%02X:%02X:%02X",
					pVb->val.bitstring[0],
					pVb->val.bitstring[1],
					pVb->val.bitstring[2],
					pVb->val.bitstring[3],
					pVb->val.bitstring[4],
					pVb->val.bitstring[5]
				);
			pValue->parameterValue = AnscCloneString(pBuff);
        } 
        else if ( AnscEqualString(pMibMapping->MibInfo.pType, "InetAddressIPv6", FALSE))
        {
            if (inet_ntop(AF_INET6, pVb->val.bitstring, pBuff, sizeof(pBuff)) != NULL)
                pValue->parameterValue = AnscCloneString(pBuff);
            /*
              _ansc_sprintf
                (
                    pBuff,
                    "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
                    pVb->val.bitstring[0],
                    pVb->val.bitstring[1],
                    pVb->val.bitstring[2],
                    pVb->val.bitstring[3],
                    pVb->val.bitstring[4],
                    pVb->val.bitstring[5],
                    pVb->val.bitstring[6],
                    pVb->val.bitstring[7],
                    pVb->val.bitstring[8],
                    pVb->val.bitstring[9],
                    pVb->val.bitstring[10],
                    pVb->val.bitstring[11],
                    pVb->val.bitstring[12],
                    pVb->val.bitstring[13],
                    pVb->val.bitstring[14],
                    pVb->val.bitstring[15]
                );
            pValue->parameterValue = AnscCloneString(pBuff);
                */
        }
        else
		{
			/* ARRISXB6-1543: An Octet String is Binary Data or Text and may not be Null terminated, in addition net-snmp uses a union
			so next memory block may not be a NULL terminator. Copy based on passed in net-snmp length to prevent extra characters */			
			if(MAX_OCTET_BUFFER_SIZE > pVb->val_len)
			{
				memcpy((char*)pBuff, (char*)pVb->val.string, pVb->val_len);
				pValue->parameterValue = AnscCloneString(pBuff);
			}
			else
			{
				AnscTraceError(("Buffer Not Large Enough: Failed to Transfer Value. Buffer Size: %d, Value Size: %d\n", MAX_OCTET_BUFFER_SIZE, pVb->val_len));
			}
		}
	}
	else if( uType == ASN_INTEGER)
	{
		if( pValue->type == ccsp_string)
		{
			/* find the enumeration string */
			pMap = CcspUtilLookforEnumMapping(&pMibMapping->MapQueue, *pVb->val.integer);

			if( pMap != NULL)
			{
				pValue->parameterValue = AnscCloneString(pMap->pString);
			}
		}
		else if( pValue->type == ccsp_boolean)
		{
			if( *pVb->val.integer != 0)
			{
				pValue->parameterValue = AnscCloneString("true");
			}
			else
			{
				pValue->parameterValue = AnscCloneString("false");
			}
		}
		else
		{
			sprintf(pBuff, "%ld", *pVb->val.integer);
			pValue->parameterValue = AnscCloneString(pBuff);
		}
	}
	else if( uType == ASN_IPADDRESS)
	{
		pValue->parameterValue = SlapVcoIp4AddrToString2(NULL, *pVb->val.integer);
	}
	else if( uType > ASN_IPADDRESS && uType <= ASN_OPAQUE)
	{
		if( pValue->type == ccsp_string)
		{
			/* find the enumeration string */
			pMap = CcspUtilLookforEnumMapping(&pMibMapping->MapQueue, *pVb->val.integer);

			if( pMap != NULL)
			{
				pValue->parameterValue = AnscCloneString(pMap->pString);
			}
		}
		else
		{
			sprintf(pBuff, "%ld", (ULONG)*pVb->val.integer);
			pValue->parameterValue = AnscCloneString(pBuff);
		}
	}
	else if( uType == ASN_BIT_STR)
	{
		/* transfer bits to string */
		if(pMibMapping->MapQueue.Depth == 0)
		{
			/* transfer to hex string */
			if( pValue->type == ccsp_string)
			{
				pValue->parameterValue = utilUcharArrayToString(pVb->val.bitstring, pVb->val_len);
			}
			else
			{
				AnscTraceError(("MIB type = %d while DM type = %d. Don't know how to translate the value.\n", uType, pValue->type));
			}
		}
		else
		{
			/* transfer the bits to string */
			pValue->parameterValue = utilBitsToDMString(pVb->val.bitstring, pVb->val_len, pMibMapping);
		}
	}
	else
	{
		AnscTraceWarning(("Unsupported MIB type: %d. Failed to transfer value.\n", uType));
	}

	return TRUE;
}


/**********************************************************************

    prototype:

		netsnmp_tdata_row*
		CcspUtilCreateMibEntry
			(
				netsnmp_tdata*				table_data,
				PULONG						pIndexArray,
				ULONG						uCount,
				BOOL						bValid
			)

    description:

        This function is called to create an SNMP Mib Entry;

    argument:   
				netsnmp_tdata*				table_data,
				The table definition

				PULONG						pIndexArray,
				The index array;

				ULONG						uCount
				The count of index;

				BOOL						bValid
				Whether it's a valid entry or not; It's not if it's created by RowStatus;

	return:     The SNMP tdata row object created

**********************************************************************/
netsnmp_tdata_row*
CcspUtilCreateMibEntry
	(
		netsnmp_tdata*				table_data,
		PULONG						pIndexArray,
		ULONG						uCount,
		BOOL						bValid
	)
{
    PCCSP_TABLE_ENTRY				entry = NULL;
	ULONG							i	  = 0;
    netsnmp_tdata_row*				row   = 0;

    entry = (PCCSP_TABLE_ENTRY)AnscAllocateMemory(sizeof(CCSP_TABLE_ENTRY));

    if (!entry)
    {		
		return NULL;
	}

    row = netsnmp_tdata_create_row();
    if (!row) 
	{
        AnscFreeMemory(entry);

        return NULL;
    }

	row->data = entry;

	for( i = 0; i < uCount; i ++)
	{
		entry->IndexValue[i].Value.uValue = pIndexArray[i];
		entry->IndexCount ++;

		netsnmp_tdata_row_add_index
			(
				row, 
				ASN_UNSIGNED,
				&pIndexArray[i],
				4
			);
	}

	if( bValid)
	{
		entry->valid = 1;
	}

	if (table_data)
    {
		netsnmp_tdata_add_row(table_data, row);
	}


    return row;
}

/**********************************************************************

    prototype:

		void
		CcspUtilRemoveMibEntry
			(
				netsnmp_tdata*				table_data,
				netsnmp_tdata_row*			row
			)

    description:

        This function is called to remove an SNMP Mib Entry;

    argument:   
				netsnmp_tdata*				table_data,
				The table definition

				netsnmp_tdata_row*			row
				The row to be removed.

	return:     None;

**********************************************************************/
void
CcspUtilRemoveMibEntry
	(
		netsnmp_tdata*				table_data,
		netsnmp_tdata_row*			row
	)
{
    PCCSP_TABLE_ENTRY				entry = NULL;

    if (!row)      return;                 /* Nothing to remove */

    entry = (PCCSP_TABLE_ENTRY) row->data;

	if(entry)
	{
		CcspUtilCleanMibValueQueue(&entry->MibValueQueue);

		AnscFreeMemory(entry);
                row->data = NULL;
	}

    if (table_data)
        netsnmp_tdata_remove_and_delete_row(table_data, row);
    else
        netsnmp_tdata_delete_row(row);

}


/**********************************************************************

    prototype:

		BOOL
		CcspUtilDeleteCosaEntry
			(
				ANSC_HANDLE					hTableHelper,
				PULONG						pIndexArray,
				ULONG						uIndexCount
			)

    description:

        This function is called to delete a DM entry when RowStatus == RS_DESTROY.

    argument:   
				ANSC_HANDLE					hTableHelper,
				The handle of TableHelper object;

				PULONG						pIndexArray,
				The index value array;

				ULONG						uIndexCount
				The count of the index

	return:     Success or failure;

**********************************************************************/
BOOL
CcspUtilDeleteCosaEntry
	(
	    ANSC_HANDLE					hTableHelper,
		PULONG						pIndexArray,
		ULONG						uIndexCount
	)
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject     = (PCCSP_TABLE_HELPER_OBJECT)hTableHelper;
    PSINGLE_LINK_ENTRY              pSLinkEntry		= (PSINGLE_LINK_ENTRY)NULL;
	ULONG							i				= 0;
	PCCSP_INDEX_MAPPING				pIndexMap       = (PCCSP_INDEX_MAPPING)NULL;
	char							pObjName[256]   = { 0 };
	char							pTmpName[256]   = { 0 };
	ULONG							pMapIndex[8]    = { 0 };

	if( uIndexCount == 0)
	{
		return FALSE;
	}

	/* Map the index to the DM instance number */
	CcspUtilMibIndexesToInsArray(&pThisObject->IndexMapQueue, pIndexArray, pMapIndex, uIndexCount);

	/* get the last index; */
	pSLinkEntry = AnscQueueGetEntryByIndex(&pThisObject->IndexMapQueue, uIndexCount - 1 );

	if( pSLinkEntry == NULL)
	{
		AnscTraceError(("Failed to get the last index. uIndexCount = %d\n", uIndexCount));
		return FALSE;
	}

	pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);

	if( pIndexMap == NULL)
	{
		AnscTraceError(("Empty Index map.\n"));
		return FALSE;
	}

	if( uIndexCount == 1)
	{
		_ansc_sprintf(pObjName, "%s%lu.", pIndexMap->Mapping.IndexMappingInfo.pTableObj, 
			pMapIndex[0]);
	}
	else if(uIndexCount == 2)
	{
		_ansc_sprintf(pTmpName, pIndexMap->Mapping.IndexMappingInfo.pTableObj, 
			pMapIndex[0]);
		_ansc_sprintf(pObjName, "%s%lu.", pTmpName, pMapIndex[1]);
	}
	else if(uIndexCount == 3)
	{
		_ansc_sprintf(pTmpName, pIndexMap->Mapping.IndexMappingInfo.pTableObj, 
			pMapIndex[0], pMapIndex[1]);
		_ansc_sprintf(pObjName, "%s%lu.", pTmpName, pMapIndex[2]);
	}
	else if(uIndexCount == 4)
	{
		_ansc_sprintf(pTmpName, pIndexMap->Mapping.IndexMappingInfo.pTableObj, 
			pMapIndex[0], pMapIndex[1], pMapIndex[2]);
		_ansc_sprintf(pObjName, "%s%lu.", pTmpName, pMapIndex[3]);
	}
	else
	{
		AnscTraceError(("Too many indexes '%lu', failed to remove Cosa Entry.\n", uIndexCount));

		return FALSE;
	}

	AnscTraceInfo(("Try to Delete COSA Entry '%s'\n", pObjName));

	return Cosa_DelEntry(pThisObject->pCcspComp, pThisObject->pCcspPath, pObjName);
}

/**********************************************************************

    prototype:

		BOOL
		CcspUtilCreateCosaEntry
			(
				ANSC_HANDLE					hTableHelper,
				PULONG						pIndexArray,
				ULONG						uIndexCount
			)

    description:

        This function is called to create a DM entry when RowStatus == RS_CREATEANDGO or RS_CREATEANDWAIT;

    argument:   
				ANSC_HANDLE					hTableHelper,
				The handle of TableHelper object;

				PULONG						pIndexArray,
				The index value array;

				ULONG						uIndexCount
				The count of the index

	return:     Success or failure;

**********************************************************************/
BOOL
CcspUtilCreateCosaEntry
	(
	    ANSC_HANDLE					hTableHelper,
		PULONG						pIndexArray,
		ULONG						uIndexCount
	)
{
	PCCSP_TABLE_HELPER_OBJECT       pThisObject     = (PCCSP_TABLE_HELPER_OBJECT)hTableHelper;
    PSINGLE_LINK_ENTRY              pSLinkEntry		= (PSINGLE_LINK_ENTRY)NULL;
	PCCSP_INDEX_MAPPING				pIndexMap       = (PCCSP_INDEX_MAPPING)NULL;
	ULONG							i				= 0;
	ULONG							j				= 0;
	char							pTmp[256]       = { 0 };
	unsigned int*				    insArray        = NULL;
	unsigned int					insCount        = 32;
	ULONG							pInsArray[8]    = {0};
	BOOL							bExist          = FALSE;
	ULONG							newIns          = 0;

	for( i = 0; i < uIndexCount; i ++)
	{
		bExist      = FALSE;
		newIns      = 0;

		pSLinkEntry = AnscQueueGetEntryByIndex(&pThisObject->IndexMapQueue, i);

		if( pSLinkEntry == NULL)  return FALSE;
		
		pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);

		pInsArray[i] = CcspUtilLookforInsNumMapping(&pIndexMap->IndexQueue, pIndexArray[i], TRUE);

		if( pInsArray[i] == 0)  pInsArray[i] = pIndexArray[i];

		if( i == 0)
		{
			AnscCopyString(pTmp, pIndexMap->Mapping.IndexMappingInfo.pTableObj);
		}
		else if( i == 1)
		{
			_ansc_sprintf(pTmp,pIndexMap->Mapping.IndexMappingInfo.pTableObj, pInsArray[0]);
		}
		else if( i == 2)
		{
			_ansc_sprintf(pTmp,pIndexMap->Mapping.IndexMappingInfo.pTableObj, pInsArray[0], pInsArray[1]);

		}
		else if (i == 3)
		{
			_ansc_sprintf(pTmp,pIndexMap->Mapping.IndexMappingInfo.pTableObj, pInsArray[0], pInsArray[1], pInsArray[2]);

		}
		else
		{
			AnscTraceError(("Cannot add entry with so many indexes: %lu\n", uIndexCount));
		}

		if( !Cosa_GetInstanceNums(pThisObject->pCcspComp, pThisObject->pCcspPath, pTmp,
				&insArray, &insCount))
		{
			insArray = NULL;
			insCount = 0;
		}

		/* check wether this instance is already there */
		for( j = 0; j < insCount; j ++)
		{
			if( pInsArray[i] == insArray[j])
			{
				bExist = TRUE;
				break;
			}
		}

        if (insArray)
        {
            free(insArray);
        }

		if( !bExist) /* if not exist, create the entry */
		{
			newIns = Cosa_AddEntry(pThisObject->pCcspComp, pThisObject->pCcspPath, pTmp);

			if( newIns == 0)
			{
				AnscTraceError(("Failed to create a CCSP entry in table '%s'\n", pTmp));

				return FALSE;
			}
			else
			{
				pInsArray[i] = newIns;

				CcspUtilAddIndexToInsMapping(&pIndexMap->IndexQueue, pIndexArray[i], newIns);

			}
		}

	}

	for( i = 0; i < uIndexCount; i ++)
	{
		pIndexArray[i] = pInsArray[i];
	}

	return TRUE;
}

/**********************************************************************

    prototype:

		BOOL
		CcspUtilMibIndexesToInsArray
			(
				PQUEUE_HEADER				pMapping,
				PULONG						indexArray,
				PULONG						insArray,
				ULONG						uIndexCount
			)

    description:

        This function is called to map indexes to Dm ins number array;

    argument:   
				PQUEUE_HEADER				pMapping,
				The index mapping array

				PULONG						indexArray,
				The mib indexes;

				PULONG						insArray,
				The DM instance numbers;

				ULONG						uIndexCount
				The count of indexes;

	return:     Success or failure;

**********************************************************************/
BOOL
CcspUtilMibIndexesToInsArray
	(
		PQUEUE_HEADER				pMapping,
		PULONG						indexArray,
		PULONG						insArray,
		ULONG						uIndexCount
	)
{
    PSINGLE_LINK_ENTRY              pSLinkEntry		= (PSINGLE_LINK_ENTRY)NULL;
	PCCSP_INDEX_MAPPING				pIndexMap       = (PCCSP_INDEX_MAPPING)NULL;
	ULONG							i				= 0;

	for( i = 0; i < uIndexCount; i ++)
	{
		pSLinkEntry = AnscQueueGetEntryByIndex(pMapping, i);
		pIndexMap   = ACCESS_CCSP_INDEX_MAPPING(pSLinkEntry);

		insArray[i] = CcspUtilLookforInsNumMapping(&pIndexMap->IndexQueue, indexArray[i], TRUE);

		if( insArray[i] == 0)
		{
			insArray[i] = indexArray[i];
		}
	}

	return TRUE;
}


/**********************************************************************

    prototype:

		char*
		CcspUtilGetDMParamName
			(
				PQUEUE_HEADER				pMapping,
				PULONG						pIndexArray,
				ULONG						uIndexCount,
				char*						pDMName
			)

    description:

        This function is called to retrieve actual mapped DM namespace based on the indexes;

    argument:   
				PQUEUE_HEADER				pMapping,
				The index mapping array

				PULONG						pIndexArray,
				The mib indexes;

				ULONG						uIndexCount
				The count of indexes;

				char*						pDMName
				The DM namespace with "%d" as instance number;

	return:     The actual DM name

**********************************************************************/
char*
CcspUtilGetDMParamName
	(
		PQUEUE_HEADER				pMapping,
		PULONG						pIndexArray,
		ULONG						uIndexCount,
		char*						pDMName
	)
{
	ULONG							pInsArray[8]  = { 0 };
	char							pTemp[256]    = { 0 };

	CcspUtilMibIndexesToInsArray(pMapping, pIndexArray, pInsArray, uIndexCount);

	if(uIndexCount  == 1)
	{
		_ansc_sprintf(pTemp, pDMName, pInsArray[0]);
	}
	else if( uIndexCount == 2)
	{
		_ansc_sprintf(pTemp, pDMName, pInsArray[0], pInsArray[1]);
	}
	else if( uIndexCount == 3)
	{
		_ansc_sprintf(pTemp, pDMName, pInsArray[0], pInsArray[1], pInsArray[2]);
	}
	else if( uIndexCount == 4)
	{
		_ansc_sprintf(pTemp, pDMName, pInsArray[0], pInsArray[1], pInsArray[2], pInsArray[3]);
	}

	return AnscCloneString(pTemp);
}


/**********************************************************************

    prototype:

		BOOL
		CcspUtilAddIndexToInsMapping
			(
				PQUEUE_HEADER				pMapping,
				ULONG						index,
				ULONG						insNum
			)

    description:

        This function is called to add new mapping after new entry was created.

    argument:   
				PQUEUE_HEADER				pMapping,
				The index mapping array

				ULONG						index,
				The new MIB index;

				ULONG						insNum
				The new instance number;

	return:     Success or failure;

**********************************************************************/
BOOL
CcspUtilAddIndexToInsMapping
	(
		PQUEUE_HEADER				pMapping,
		ULONG						index,
		ULONG						insNum
    )
{
	PCCSP_INS_NUMBER_MAP			pMap				= (PCCSP_INS_NUMBER_MAP)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry         = (PSINGLE_LINK_ENTRY)NULL;
    
    pSLinkEntry = AnscQueueGetFirstEntry(pMapping);

    while ( pSLinkEntry )
    {
        pMap         = ACCESS_CCSP_INS_NUMBER_MAP(pSLinkEntry);
        pSLinkEntry  = AnscQueueGetNextEntry(pSLinkEntry);

		if( pMap != NULL && pMap->uMibValue == index)
		{
			pMap->uDMValue = insNum;

			return TRUE;
		}
    }

	/* add a new one */
	pMap = (PCCSP_INS_NUMBER_MAP)AnscAllocateMemory(sizeof(CCSP_INS_NUMBER_MAP));

	if( pMap != NULL)
	{
		pMap->uMibValue  = index;
		pMap->uDMValue   = insNum;

		AnscQueuePushEntry(pMapping, &pMap->Linkage);

		return TRUE;
	}

	return FALSE;
}
