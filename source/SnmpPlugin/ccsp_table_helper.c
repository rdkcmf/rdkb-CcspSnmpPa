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

        This is the implementation of object "CCSP_TABLE_HELPER_OBJECT"

        The implementation of function:
        *   CcspCreateTableHelper

        The implementation of local functions:
        *   CcspTableHelperRemove

  ------------------------------------------------------------------------------

    revision:

        05/02/2012    initial revision.

**********************************************************************************/
#include "ansc_platform.h"
#include "ccsp_mib_helper.h"
#include "ccsp_table_helper.h"
#include "ccsp_table_helper_internal.h"
#include "ccsp_mib_utilities.h"

/**********************************************************************

    prototype:

    void*
    CcspCreateTableHelper
        (
        );

    description:

        This function is called to create an object of "CCSP_TABLE_HELPER_OBJECT".

    argument:   None

	return:     The handle of the object;

**********************************************************************/
void*
CcspCreateTableHelper
	(
	)
{
	PCCSP_TABLE_HELPER_OBJECT			pThisObject        = NULL;

	pThisObject = (PCCSP_TABLE_HELPER_OBJECT)AnscAllocateMemory(sizeof(CCSP_TABLE_HELPER_OBJECT));

	if( pThisObject == NULL)
	{
		return NULL;
	}

	AnscZeroMemory((void*)pThisObject, sizeof(CCSP_TABLE_HELPER_OBJECT));

	pThisObject->bHasWritable	         = FALSE;
	pThisObject->uRowStatus              = 0;
	pThisObject->uMaxOid		         = 0;
	pThisObject->uMinOid		         = 0;
	pThisObject->uOidLen                 = 0;
	pThisObject->uCacheTimeout           = 45;
	pThisObject->HandleRequestsCallback  = NULL;
	pThisObject->RefreshCacheCallback    = NULL;
	pThisObject->pCcspComp				 = NULL;
	pThisObject->pCcspPath				 = NULL;
	pThisObject->mibMagic.pMibHandler    = (void*)pThisObject;

	pThisObject->LoadMibs        		 = CcspTableHelperLoadMibs;
	pThisObject->Remove					 = CcspTableHelperRemove;
	pThisObject->RegisterMibHandler		 = CcspTableHelperRegisterMibHandler;
	pThisObject->RefreshCache            = CcspTableHelperRefreshCache;
	pThisObject->SetMibValues            = CcspTableHelperSetMibValues;
	pThisObject->GetMibValues            = CcspTableHelperGetMibValues;

    /* init the queues */
    AnscQueueInitializeHeader(&pThisObject->MibObjQueue);
    AnscQueueInitializeHeader(&pThisObject->IndexMapQueue);

	return (void*)pThisObject;
}

/**********************************************************************

    prototype:

    void
    CcspTableHelperRemove
        (
			ANSC_HANDLE				hThisObject
        );

    description:

        This function is called to remove the memory of object "CCSP_TABLE_HELPER_OBJECT".

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

	return:     None

**********************************************************************/
void
CcspTableHelperRemove
	(
			ANSC_HANDLE				hThisObject
	)
{
	PCCSP_TABLE_HELPER_OBJECT      pThisObject  = (PCCSP_TABLE_HELPER_OBJECT)hThisObject;

	CcspUtilCleanMibObjQueue(&pThisObject->MibObjQueue);
	CcspUtilCleanIndexMapQueue(&pThisObject->IndexMapQueue);

	if( pThisObject->pCcspComp != NULL)
	{
		AnscFreeMemory(pThisObject->pCcspComp);
	}

	if( pThisObject->pCcspPath != NULL)
	{
		AnscFreeMemory(pThisObject->pCcspPath);
	}

	AnscFreeMemory(hThisObject);
}

