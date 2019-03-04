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


/**********************************************************************

    module: ccsp_mib_utilities.h

        For CCSP SnmpAgent PA

    ---------------------------------------------------------------

    description:

        This header file contains utility functions will be used 
		by CCSP SnmpAgent handler.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        05/02/2012    initial revision.

**********************************************************************/


#ifndef  _CCSP_MIB_UTILITIES_H
#define  _CCSP_MIB_UTILITIES_H

#include "ccsp_mib_definitions.h"

/* Some Node Names used in XML Node */
#define CCSP_XML_Scalar_name                           "name"
#define CCSP_XML_Scalar_baseOid                        "baseOid"
#define CCSP_XML_Scalar_enabled                        "enabled"
#define CCSP_XML_Scalar_cacheTimeout                   "cacheTimeout"
#define CCSP_XML_Scalar_mapToEntry                     "mapToEntry"
#define CCSP_XML_Scalar_callbacks                      "callbacks"
#define CCSP_XML_Scalar_handleRequests                 "handleRequests"
#define CCSP_XML_Scalar_mapping                        "mapping"

#define CCSP_XML_Table_name                            "name"
#define CCSP_XML_Table_tableOid                        "tableOid"
#define CCSP_XML_Table_enabled                         "enabled"
#define CCSP_XML_Table_writable                        "writable"
#define CCSP_XML_Table_maxEntries                      "maxEntries"
#define CCSP_XML_Table_cacheTimeout                    "cacheTimeout"
#define CCSP_XML_Table_cacheSkip                       "cacheSkip"
#define CCSP_XML_Table_callbacks                       "callbacks"
#define CCSP_XML_Table_handleRequests                  "handleRequests"
#define CCSP_XML_Table_refreshCache                    "refreshCache"
#define CCSP_XML_Table_index                           "index"
#define CCSP_XML_Table_mapping                         "mapping"

#define CCSP_XML_MibInfo_lastOid					   "lastOid"
#define CCSP_XML_MibInfo_name  					       "name"
#define CCSP_XML_MibInfo_access                        "access"
#define CCSP_XML_MibInfo_dataType					   "dataType"
#define CCSP_XML_MibInfo_range                         "range"
#define CCSP_XML_MibInfo_min						   "min"
#define CCSP_XML_MibInfo_max                           "max"

#define CCSP_XML_DMInfo_paramName                      "paramName"
#define CCSP_XML_DMInfo_dataType                       "dataType"
#define CCSP_XML_DMInfo_enumeration                    "enumeration"
#define CCSP_XML_DMInfo_bitmask                        "bitmask"
#define CCSP_XML_DMInfo_background                     "background"

#define CCSP_XML_IndexInfo_tableObj                    "tableObj"
#define CCSP_XML_IndexInfo_map                         "map"
#define CCSP_XML_IndexInfo_from                        "from"
#define CCSP_XML_IndexInfo_to                          "to"
#define CCSP_XML_IndexInfo_subDm                       "subDM"

#define CCSP_XML_MibMap_mib                            "mib"
#define CCSP_XML_MibMap_dm                             "dm"

#define CCSP_XML_IndexMap_mib                          "mib"
#define CCSP_XML_IndexMap_mapToInsNumber               "mapToInsNumber"
#define CCSP_XML_IndexMap_dm                           "dm"
#define CCSP_XML_IndexMap_subDm                        "mapToSubDM"

/***********************************************************
        FUNCTIONS IMPLEMENTED IN CCSP_MIB_UTILITIES.C
***********************************************************/
void
CcspUtilCleanMibValueQueue
    (
        PQUEUE_HEADER               pQueue
    );

void
CcspUtilCleanMibObjQueue
    (
        PQUEUE_HEADER               pQueue
    );

void
CcspUtilCleanIndexMapQueue
    (
        PQUEUE_HEADER               pQueue
    );

void
CcspUtilCleanMibMapping
    (
        PCCSP_MIB_MAPPING   		pMapping
    );

void
CcspUtilCleanIndexMapping
    (
        PCCSP_INDEX_MAPPING  		pMapping
    );

BOOL
CcspUtilParseOidValueString
	(
		char*						pOidString,
		oid*                        pArray,
		PULONG						pSize
	);

ULONG
CcspUtilMIBStringToDataType
    (
        char*						pBuffer
    );


ULONG
CcspUtilTR69StringToDataType
    (
        char*						pBuffer
    );

void
CcspUtilTR69DataTypeToString
    (
		ULONG						uDataType,
        char*						pBuffer
    );

BOOL
CcspUtilLoadMibInfo
	(
		PCCSP_MIB_INFO				pInfo,
        PQUEUE_HEADER               pQueue,
		ANSC_HANDLE					hXmlHandle
	);

BOOL
CcspUtilLoadDMMappingInfo
	(
		PCCSP_DM_MAPPING_INFO   	pInfo,
        PQUEUE_HEADER               pQueue,
		ANSC_HANDLE					hXmlHandle
	);

BOOL
CcspUtilLoadIndexMappingInfo
	(
		PCCSP_INDEX_MAPPING_INFO   	pInfo,
		PQUEUE_HEADER               pQueue,
		ANSC_HANDLE					hXmlHandle
	);

PCCSP_MIB_MAPPING
CcspUtilLoadMibMappingInfo
	(
		ANSC_HANDLE					hXmlHandle
	);

PCCSP_INDEX_MAPPING
CcspUtilLoadIndexMapping
	(
		ANSC_HANDLE					hXmlHandle
	);

BOOL
CcspUtilParseEnumString
	(
		char*						pEnumString,
		PQUEUE_HEADER               pQueue
    );

void
CcspUtilTraceOid
	(
		oid*						pOid,
		ULONG						uLength
	);

void
CcspUtilInitMibValueArray
	(
		PQUEUE_HEADER				pMibObjQueue,
		PQUEUE_HEADER				pMibValueQueue
	);	

PCCSP_MIB_VALUE
CcspUtilLookforMibValueObjWithOid
	(
		PQUEUE_HEADER				pMibValueQueue,
		oid							uLastOid
	);	

PCCSP_MIB_MAPPING
CcspUtilLookforMibMapWithOid
	(
		PQUEUE_HEADER				pMibMappingQueue,
		oid							uLastOid
	);	

PCCSP_INT_STRING_MAP
CcspUtilLookforEnumMapping
	(
		PQUEUE_HEADER				pMapping,
		ULONG						enumCode
	);	

int
CcspUtilLookforEnumStrInMapping
	(
		PQUEUE_HEADER				pMapping,
		char*						pString
	);	

int
CcspUtilLookforInsNumMapping
	(
		PQUEUE_HEADER				pMapping,
		ULONG						uValue,
		BOOL						bIsMibValue
	);	

ULONG
CcspUtilDMFilterToNamespace
	(
		char*						pDMFilter,
		char**						ppDestName,
		char**						ppDestPath
	);	

BOOL
CcspUtilDMValueToMIB
	(
		PCCSP_MIB_MAPPING			pMibMapping,
		PCCSP_MIB_VALUE				pMibValue, 
		int							uDMType,
		char*						pValue
	);

BOOL
CcspUtilMIBValueToDM
	(
		PCCSP_MIB_MAPPING			pMibMapping,
		void*						pValue,
		netsnmp_variable_list*		pVb
	);

netsnmp_tdata_row*
CcspUtilCreateMibEntry
	(
		netsnmp_tdata*				table_data,
		PULONG						pIndexArray,
		ULONG						uCount,
		BOOL						bValid
	);

void
CcspUtilRemoveMibEntry
	(
		netsnmp_tdata*				table_data,
		netsnmp_tdata_row*			row
	);

BOOL
CcspUtilDeleteCosaEntry
	(
	    ANSC_HANDLE					pTableHelper,
		PULONG						pIndexArray,
		ULONG						uIndexCount
	);

BOOL
CcspUtilCreateCosaEntry
	(
	    ANSC_HANDLE					pTableHelper,
		PULONG						pIndexArray,
		ULONG						uIndexCount
	);

BOOL
CcspUtilMibIndexesToInsArray
	(
		PQUEUE_HEADER				pMapping,
		PULONG						indexArray,
		PULONG						insArray,
		ULONG						uIndexCount
	);

char*
CcspUtilGetDMParamName
	(
		PQUEUE_HEADER				pMapping,
		PULONG						pIndexArray,
		ULONG						uIndexCount,
		char*						pDMName
	);

BOOL
CcspUtilAddIndexToInsMapping
	(
		PQUEUE_HEADER				pMapping,
		ULONG						index,
		ULONG						insNum
    );

#endif
