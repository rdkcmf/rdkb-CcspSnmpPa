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

    module: ccsp_scalar_helper_internal.h

        For CCSP SnmpAgent PA

    ---------------------------------------------------------------

    description:

        This header file contains the internal functions used by
		object CCSP_SCALAR_HELPER_OBJECT.

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
#ifndef  _CCSP_SCALAR_HELPER_INTERNAL_H
#define  _CCSP_SCALAR_HELPER_INTERNAL_H

/***********************************************************
        FUNCTIONS IMPLEMENTED IN CCSP_MIB_HELPER.C
***********************************************************/
void
CcspScalarHelperRemove
    (
        ANSC_HANDLE                 hThisObject
    );

/***********************************************************
        FUNCTIONS IMPLEMENTED IN CCSP_MIB_HELPER_CONTROL.C
***********************************************************/
BOOL
CcspScalarHelperLoadMibs
    (
        ANSC_HANDLE                 hThisObject,
		void*						hXmlHandle,
		void*						hLibHandle
    );

void
CcspScalarHelperRegisterMibHandler
    (
        ANSC_HANDLE                 hThisObject
    );

/***********************************************************
        FUNCTIONS IMPLEMENTED IN CCSP_MIB_HELPER_ACCESS.C
***********************************************************/
int
CcspScalarHelperGetMibValues
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	);

int
CcspScalarHelperSetMibValues
	(
        ANSC_HANDLE                 hThisObject,
        netsnmp_agent_request_info  *reqinfo,
        netsnmp_request_info		*requests
	);

int
CcspScalarHelperRefreshCache
	(
        ANSC_HANDLE                 hThisObject
	);

void
CcspScalarHelperClearCache
	(
        ANSC_HANDLE                 hThisObject
	);

#endif
