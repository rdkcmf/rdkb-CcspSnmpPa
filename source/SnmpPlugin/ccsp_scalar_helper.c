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

        This is the implementation of object "CCSP_SCALAR_HELPER_OBJECT"

        The implementation of function:
        *   CcspCreateScalarHelper

        The implementation of local functions:
        *   CcspScalarHelperRemove

  ------------------------------------------------------------------------------

    revision:

        05/02/2012    initial revision.

**********************************************************************************/
#include "ansc_platform.h"
#include "ccsp_mib_helper.h"
#include "ccsp_scalar_helper.h"
#include "ccsp_scalar_helper_internal.h"
#include "ccsp_mib_utilities.h"

/**********************************************************************

    prototype:

    void*
    CcspCreateScalarHelper
        (
        );

    description:

        This function is called to create an object of "CCSP_SCALAR_HELPER_OBJECT".

    argument:   None

	return:     The handle of the object;

**********************************************************************/
void*
CcspCreateScalarHelper
	(
	)
{
	PCCSP_SCALAR_HELPER_OBJECT			pThisObject        = NULL;

	pThisObject = (PCCSP_SCALAR_HELPER_OBJECT)AnscAllocateMemory(sizeof(CCSP_SCALAR_HELPER_OBJECT));

	if( pThisObject == NULL)
	{
		return NULL;
	}

	AnscZeroMemory((void*)pThisObject, sizeof(CCSP_SCALAR_HELPER_OBJECT));

	pThisObject->pMibFilter		         = 0;
	pThisObject->bHasWritable	         = FALSE;
	pThisObject->uMaxOid		         = 0;
	pThisObject->uMinOid		         = 0;
	pThisObject->uOidLen                 = 0;
	pThisObject->uCacheTimeout           = 30;
	pThisObject->HandleRequestsCallback  = NULL;
	pThisObject->pCcspComp				 = NULL;
	pThisObject->pCcspPath				 = NULL;
	pThisObject->nCacheMibCount          = 0;

	pThisObject->LoadMibs        		 = CcspScalarHelperLoadMibs;
	pThisObject->Remove					 = CcspScalarHelperRemove;
	pThisObject->RegisterMibHandler		 = CcspScalarHelperRegisterMibHandler;
	pThisObject->RefreshCache            = CcspScalarHelperRefreshCache;
	pThisObject->ClearCache              = CcspScalarHelperClearCache;
	pThisObject->SetMibValues            = CcspScalarHelperSetMibValues;
	pThisObject->GetMibValues            = CcspScalarHelperGetMibValues;

    /* init the queues */
    AnscQueueInitializeHeader(&pThisObject->MibValueQueue);
    AnscQueueInitializeHeader(&pThisObject->MibObjQueue);

	return (void*)pThisObject;
}

/**********************************************************************

    prototype:

    void
    CcspScalarHelperRemove
        (
			ANSC_HANDLE				hThisObject
        );

    description:

        This function is called to remove the memory of object "CCSP_SCALAR_HELPER_OBJECT".

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

	return:     None

**********************************************************************/
void
CcspScalarHelperRemove
	(
			ANSC_HANDLE				hThisObject
	)
{
	PCCSP_SCALAR_HELPER_OBJECT      pThisObject  = (PCCSP_SCALAR_HELPER_OBJECT)hThisObject;

    CcspUtilCleanMibValueQueue(&pThisObject->MibValueQueue);
	CcspUtilCleanMibObjQueue(&pThisObject->MibObjQueue);

	if( pThisObject->pCcspComp != NULL)
	{
		AnscFreeMemory(pThisObject->pCcspComp);
	}

	if( pThisObject->pCcspPath != NULL)
	{
		AnscFreeMemory(pThisObject->pCcspPath);
	}

	if(pThisObject->pMibFilter != NULL)
	{
		AnscFreeMemory(pThisObject->pMibFilter);
	}

	AnscFreeMemory(hThisObject);
}

