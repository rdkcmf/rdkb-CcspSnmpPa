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

    module: ccsp_table_helper.h

        For CCSP SnmpAgent PA

    ---------------------------------------------------------------

    description:

        This wrapper file defines all the platform-independent
        functions and macros for CCSP Table MIB Helper

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin     Zhu 

    ---------------------------------------------------------------

    revision:

        05/09/2012    initial revision.

**********************************************************************/


#ifndef  _CCSP_TABLE_HELPER_H_
#define  _CCSP_TABLE_HELPER_H_

#include "ccsp_mib_definitions.h"

/***********************************************************
       CCSP MIB HELPER OBJECT DEFINITION
***********************************************************/

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support),
 * we have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  int
(*PFN_CCSP_TABLE_REFRESH)
    (
        ANSC_HANDLE                 hThisObject
    );


typedef  void
(*PFN_CCSP_TABLE_ACTION)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  BOOL
(*PFN_CCSP_TABLE_LOAD)
    (
        ANSC_HANDLE                 hThisObject,
		void*						hXmlHandle,
		void*						hLibHandle
    );

typedef int
(*PFN_CCSP_TABLE_WORK)
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	);

#define  CCSP_TABLE_HELPER_CLASS_CONTENT                                                 \
    SINGLE_LINK_ENTRY               Linkage;                                              \
	char							MibName[MAXI_CCSP_MIB_GROUP_NAME_LEN];                 \
	oid                             BaseOid[MAXI_CCSP_OID_LENGTH];                         \
	ULONG							uOidLen;                                               \
	ULONG							uMinOid;                                               \
	ULONG							uMaxOid;                                               \
	ULONG							uRowStatus;                                            \
    BOOL							bHasWritable;                                          \
    BOOL							bBackground;                                          \
	ULONG							uCacheTimeout;                                         \
    BOOL                            bCacheSkip;                                             \
	void*							HandleRequestsCallback;                                \
	void*							RefreshCacheCallback;                                  \
	CCSP_MIB_TABLE_MAGIC            mibMagic;                                              \
	/* queue of CCSP_MIB_MAPPING */                                                        \
    QUEUE_HEADER                    MibObjQueue;                                           \
	/* queue of CCSP_INDEX_MAPPING */                                                      \
    QUEUE_HEADER                    IndexMapQueue;                                         \
	char                            pStrSampleDM[MAXI_DM_NAME_LENGTH];                     \
    char*							pCcspComp;                                             \
    char*							pCcspPath;                                             \
                                                                                            \
    PFN_CCSP_TABLE_LOAD             LoadMibs;                                               \
    PFN_CCSP_TABLE_ACTION           RegisterMibHandler;                                     \
    PFN_CCSP_TABLE_ACTION           Remove;                                                 \
    PFN_CCSP_TABLE_REFRESH          RefreshCache;                                           \
	PFN_CCSP_TABLE_WORK				SetMibValues;                                           \
	PFN_CCSP_TABLE_WORK             GetMibValues;                                           \
    /* end of object class content */                                                       \

typedef  struct
_CCSP_TABLE_HELPER_OBJECT
{
    CCSP_TABLE_HELPER_CLASS_CONTENT
}
CCSP_TABLE_HELPER_OBJECT,  *PCCSP_TABLE_HELPER_OBJECT;

#define  ACCESS_CCSP_TABLE_HELPER_OBJECT(p)       \
         ACCESS_CONTAINER(p, CCSP_TABLE_HELPER_OBJECT, Linkage)

/* external functions to create PCCSP_TABLE_HELPER_OBJECT; */
void*
CcspCreateTableHelper();

#endif
