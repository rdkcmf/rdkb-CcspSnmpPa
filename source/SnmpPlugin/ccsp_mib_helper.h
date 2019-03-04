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

    module: ccsp_mib_helper.h

        For CCSP SnmpAgent PA

    ---------------------------------------------------------------

    description:

        This wrapper file defines all the platform-independent
        functions and macros for CCSP SnmpAgent Helper

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin     Zhu 

    ---------------------------------------------------------------

    revision:

        05/01/2012    initial revision.

**********************************************************************/


#ifndef  _CCSP_MIB_HELER_H_
#define  _CCSP_MIB_HELER_H_


/***********************************************************
       CCSP MIB HELPER OBJECT DEFINITION
***********************************************************/

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support),
 * we have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  void
(*PFN_CCSPMIBHLP_ACTION)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  BOOL
(*PFN_CCSPMIBHLP_LOAD)
    (
        ANSC_HANDLE                 hThisObject,
		char*						pMibFileName
    );

#define  MAX_CCSP_MIB_LIBRARY       16

#define  CCSP_MIB_HELPER_OBJ_CLASS_CONTENT                                                 \
    QUEUE_HEADER                    sScalarQueue;                                          \
    QUEUE_HEADER                    sTableQueue;											\
	void*							hLibArray[MAX_CCSP_MIB_LIBRARY];                        \
	ULONG							uLibCount;                                              \
                                                                                            \
    PFN_CCSPMIBHLP_LOAD             LoadCcspMibFile;                                        \
    PFN_CCSPMIBHLP_ACTION           Remove;                                                 \
    /* end of object class content */                                                       \

typedef  struct
_CCSP_MIB_HELPER_OBJECT
{
    CCSP_MIB_HELPER_OBJ_CLASS_CONTENT
}
CCSP_MIB_HELPER_OBJECT,  *PCCSP_MIB_HELPER_OBJECT;

/* external functions to create PCCSP_MIB_HELPER_OBJECT; */
void*
CcspCreateMibHelper();

#endif
