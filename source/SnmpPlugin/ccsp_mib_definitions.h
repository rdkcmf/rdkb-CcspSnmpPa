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

    module:	ccsp_mib_definitions.h

        For CCSP SnmpAgent PA

    ---------------------------------------------------------------

    description:

        This file defines the CCSP MIB related variables.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        05/01/12    initial revision.

**********************************************************************/
#ifndef  _CCSP_MIB_DEFINITIONS_
#define  _CCSP_MIB_DEFINITIONS_

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>


#define  MAXI_MIB_COUNT_IN_GROUP                128
#define  MAXI_MIB_INDEX_COUNT                   6

#define  MAXI_CCSP_OID_LENGTH                   64
#define  MAXI_STRING_INDEX_LENGTH				192
#define  MAXI_CCSP_MIB_GROUP_NAME_LEN           64
#define  MAXI_DM_NAME_LENGTH				    256
#define  MAXI_CCSP_MAP_STRING_LEN               32
#define  MAXI_MIB_DATA_TYPE_LEN                 32

/* TR69 data type definition 
 */
#define  CCSP_TR69_DataType_string              0
#define  CCSP_TR69_DataType_int                 1
#define  CCSP_TR69_DataType_unsignedInt         2
#define  CCSP_TR69_DataType_boolean             3
#define  CCSP_TR69_DataType_dateTime            4
#define  CCSP_TR69_DataType_base64              5

#define  CCSP_TR69_STR_DataType_string          "string"
#define  CCSP_TR69_STR_DataType_int             "int"
#define  CCSP_TR69_STR_DataType_unsignedInt     "unsignedInt"
#define  CCSP_TR69_STR_DataType_boolean         "boolean"
#define  CCSP_TR69_STR_DataType_dateTime        "dateTime"
#define  CCSP_TR69_STR_DataType_base64          "base64"

/* CCSP Data Limit definition */
#define  CCSP_MIB_NO_LIMIT          0
#define  CCSP_MIB_LIMIT_MIN         1
#define  CCSP_MIB_LIMIT_MAX         2
#define  CCSP_MIB_LIMIT_BOTH        3
#define  CCSP_MIB_DEFAULT_LIMIT     4

typedef void (* CCSP_CLEAN_MIB_VAL_QUEUE_FUN_PTR)(void *);

/* Counter64 defintion */
typedef  struct
_CCSP_U64
{
	ULONG							uHigh;
	ULONG							uLow;
}
CCSP_U64;

/* MIB basic defintion */
typedef  struct
_CCSP_MIB_INFO
{
	ULONG							uLastOid;
	char							pType[MAXI_MIB_DATA_TYPE_LEN];
    ULONG							uType;  
	BOOL							bWritable;
	ULONG							uMaskLimit;
	int								nMin;
	int							    nMax;
	BOOL							bIsRowStatus;
}
CCSP_MIB_INFO,  *PCCSP_MIB_INFO;

/* Define INDEX MIB Mapping Information */
typedef  struct
_CCSP_INS_NUMBER_MAP
{
    SINGLE_LINK_ENTRY               Linkage;
	ULONG						    uMibValue; /* from */
	ULONG							uDMValue;  /* to */
}
CCSP_INS_NUMBER_MAP,  *PCCSP_INS_NUMBER_MAP;

#define  ACCESS_CCSP_INS_NUMBER_MAP(p)       \
         ACCESS_CONTAINER(p, CCSP_INS_NUMBER_MAP, Linkage)

typedef  struct
_CCSP_INDEX_MAPPING_INFO
{
	char							pTableObj[MAXI_DM_NAME_LENGTH];
}
CCSP_INDEX_MAPPING_INFO,  *PCCSP_INDEX_MAPPING_INFO;

/* Define TR DataModel Mapping Information */
typedef  struct
_CCSP_INT_STRING_MAP
{
    SINGLE_LINK_ENTRY               Linkage;
	char*                           pString;
	ULONG							EnumCode;
}
CCSP_INT_STRING_MAP,  *PCCSP_INT_STRING_MAP;

#define  ACCESS_CCSP_INS_STRING_MAP(p)       \
         ACCESS_CONTAINER(p, CCSP_INT_STRING_MAP, Linkage)

#define  CcspMibFreeIntStringMaping(token_value)                                            \
         {                                                                                  \
            if ( token_value->pString )                                                     \
            {                                                                               \
                AnscFreeMemory(token_value->pString);                                       \
            }                                                                               \
                                                                                            \
            AnscFreeMemory((void*)token_value);                                             \
         }


typedef  struct
_CCSP_DM_MAPPING_INFO
{
	char							pDMName[MAXI_DM_NAME_LENGTH];
	ULONG							uDataType;
	BOOL							backgroundCommit;
}
CCSP_DM_MAPPING_INFO,  *PCCSP_DM_MAPPING_INFO;

typedef  struct
_CCSP_SUBDM_INDEX_MAPPING_INFO
{
	char							pTableObj[MAXI_DM_NAME_LENGTH];
	char							pSubDMName[MAXI_DM_NAME_LENGTH];
}
CCSP_SUBDM_INDEX_MAPPING_INFO,  *PCCSP_SUBDM_INDEX_MAPPING_INFO;

#define  CCSP_MIB_NO_MAPPING        0
#define  CCSP_MIB_MAP_TO_DM         1
#define  CCSP_MIB_MAP_TO_INSNUMBER  2
#define  CCSP_MIB_MAP_TO_SUBDM      3

/* Define an Index MIB mapping */
typedef  struct
_CCSP_INDEX_MAPPING
{
    SINGLE_LINK_ENTRY               Linkage;
	CCSP_MIB_INFO                   MibInfo;
	ULONG							uMapType;
    union
    {
  	    CCSP_DM_MAPPING_INFO        DMMappingInfo;
		CCSP_INDEX_MAPPING_INFO     IndexMappingInfo;
		CCSP_SUBDM_INDEX_MAPPING_INFO  SubDMMappingInfo;
    }Mapping;
	QUEUE_HEADER                    IndexQueue;  /* int to int mapping */
}
CCSP_INDEX_MAPPING,  *PCCSP_INDEX_MAPPING;

#define  ACCESS_CCSP_INDEX_MAPPING(p)       \
         ACCESS_CONTAINER(p, CCSP_INDEX_MAPPING, Linkage)

/* Define a MIB mapping */
typedef  struct
_CCSP_MIB_MAPPING
{
    SINGLE_LINK_ENTRY               Linkage;
	CCSP_MIB_INFO                   MibInfo;
	CCSP_DM_MAPPING_INFO            Mapping;
	QUEUE_HEADER                    MapQueue;  /* int to string maping */
	BOOL							bHasMapping;
}
CCSP_MIB_MAPPING,  *PCCSP_MIB_MAPPING;

#define  ACCESS_CCSP_MIB_MAPPING(p)       \
         ACCESS_CONTAINER(p, CCSP_MIB_MAPPING, Linkage)

/* Define an Index value object */
typedef  struct
_CCSP_MIB_INDEX_VALUE
{
    SINGLE_LINK_ENTRY               Linkage;
	ULONG							uLastOid;
    ULONG							uType;    /* ASN_INTEGER, ASN_UNSIGNED, ASN_OCTET_STR */
	BOOL							bWritable;
	ULONG							uSize;
    union
    {
        ULONG                       uValue;
        int							iValue;
		char						strValue[MAXI_STRING_INDEX_LENGTH];
		U64                         u64Value;
    }Value;
}
CCSP_MIB_INDEX_VALUE,  *PCCSP_MIB_INDEX_VALUE;

#define  ACCESS_CCSP_MIB_INDEX_VALUE(p)       \
         ACCESS_CONTAINER(p, CCSP_MIB_INDEX_VALUE, Linkage)

/* Define a MIB value object */
typedef  struct
_CCSP_MIB_VALUE
{
    SINGLE_LINK_ENTRY               Linkage;
	ULONG							uLastOid;
    ULONG							uType;  
	ULONG							uSize;
    union
    {
        ULONG                       uValue;
        int							iValue;
		char*						pBuffer;
		UCHAR*                      puBuffer;
		U64                         u64Value;
    }Value;
	ULONG							uBackSize;
    union
    {
        ULONG                       uValue;
        int							iValue;
		char*						pBuffer;
		UCHAR*                      puBuffer;
		U64                         u64Value;
    }BackValue;
}
CCSP_MIB_VALUE,  *PCCSP_MIB_VALUE;

#define  ACCESS_CCSP_MIB_VALUE(p)       \
         ACCESS_CONTAINER(p, CCSP_MIB_VALUE, Linkage)

/* Define a generic CCSP MIB table entry structure */
typedef  struct
_CCSP_TABLE_ENTRY
{
	CCSP_CLEAN_MIB_VAL_QUEUE_FUN_PTR CleanMibValueQueueFunctionPtr;
	CCSP_MIB_INDEX_VALUE            IndexValue[MAXI_MIB_INDEX_COUNT];
	ULONG							IndexCount;
	QUEUE_HEADER                    MibValueQueue;
	int								valid;
}
CCSP_TABLE_ENTRY,  *PCCSP_TABLE_ENTRY;

/*
 * MIB Table Magic handle definition
 * Will be used in the MIB implementation
 */
typedef  struct
_CCSP_MIB_TABLE_MAGIC
{
    void*		                    pTableData;
	void*							pMibHandler;
}
CCSP_MIB_TABLE_MAGIC,  *PCCSP_MIB_TABLE_MAGIC;

#endif
