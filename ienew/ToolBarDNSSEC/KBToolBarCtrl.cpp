/* ***** BEGIN LICENSE BLOCK *****
Copyright 2012 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator Add-on.

DNSSEC Validator Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.

Some parts of these codes are based on the DNSSECVerify4IENav project
<http://cs.mty.itesm.mx/dnssecmx>, which is distributed under the Code Project
Open License (CPOL), see <http://www.codeproject.com/info/cpol10.aspx>.
***** END LICENSE BLOCK ***** */

#include "stdafx.h"
#include "resource.h"
#include "KBToolBarCtrl.h"
#include "KBBar.h"
#include "KBBarBand.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//-------------------------------------------------------------------
// Definition of toolbar style
//-------------------------------------------------------------------
const DWORD DEFAULT_TOOLBAR_STYLE = 
		 WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE | WS_BORDER |
		 TBSTYLE_FLAT | TBSTYLE_TRANSPARENT |	BS_BITMAP |					
		 CCS_TOP | CCS_NODIVIDER | CCS_NOPARENTALIGN | CCS_NORESIZE;

/////////////////////////////////////////////////////////////////////////////
// CKBToolBarCtrl
//Constructor of CKBToolBarCtrl 
CKBToolBarCtrl::CKBToolBarCtrl()
{
}
//Destructor of CKBToolBarCtrl
CKBToolBarCtrl::~CKBToolBarCtrl()
{
}
//Default messages for CKBToolBarCtrl
BEGIN_MESSAGE_MAP(CKBToolBarCtrl, CToolBarCtrl)
	//{{AFX_MSG_MAP(CKBToolBarCtrl)
	ON_WM_SIZE()
	ON_WM_KEYDOWN()
	ON_CONTROL_REFLECT(0, OnCommand)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CKBToolBarCtrl operations
//----------------------------------------------------------------
// Default creation code, create of toolbar with one bitmap button 
//----------------------------------------------------------------
bool CKBToolBarCtrl::Create(CRect rcClientParent, CWnd* pWndParent, CKBBarBand* pBand, WORD icon) 
{
	ATLTRACE("CreateToolbar():\n");
	if (!CToolBarCtrl::Create(DEFAULT_TOOLBAR_STYLE, rcClientParent, pWndParent, icon))
		return false;	

	// Generation of Bitmap List Index
	for (int i=0; i<BITMAP_NUMBER; i++) {
		if (AddBitmap(1, StatusBitmap[i]) == -1)
		{
			DWORD dwError = ::GetLastError();
			return false;	
		}//if
	}//for

	// set button properties
	TBBUTTON tbs;
		tbs.dwData = 0;
		tbs.fsState = TBSTATE_ENABLED;
		tbs.fsStyle = TBSTYLE_BUTTON;
		tbs.iBitmap = 0;
		tbs.idCommand = ID_BUTTON1;
		tbs.iString = 0;
	// add button into toolbar
	if (!AddButtons(1, &tbs))
		return false;
	// set handle on this window	
	m_pBand = pBand;
	return true;
}

//-----------------------------------------------------------------------
//I dont know, what is it or what to do it. May be message filter TRACE 
//------------------------------------------------------------------------
STDMETHODIMP CKBToolBarCtrl::TranslateAcceleratorIO(LPMSG pMsg)
{
ATLTRACE("TranslateAcceleratorIO():\n");
TRACE(_T("toolbarctrl::TAIO -- msg = %d | vk = %d\n"), pMsg->message, (int)pMsg->wParam);
	return S_FALSE;
}

//-----------------------------------------------------------------------
// Handles any commands executed by this toolbar -- including buttons
//-----------------------------------------------------------------------
void CKBToolBarCtrl::OnCommand()
{	//Save current massage from toolbar
	const MSG* pMsg = GetCurrentMessage();
	int nID = LOWORD(pMsg->wParam);
	_variant_t varEmpty;
	_variant_t varURL;
	//Button action - change URL in IE browser 
	switch (nID)
	{
	case ID_BUTTON1:
		ATLTRACE("OnCommandButton():\n");
		//varURL = _bstr_t(g_MSDNURL);
		//m_pBand->m_pIE->Navigate2(&varURL, &varEmpty, &varEmpty, &varEmpty, &varEmpty);		
		m_pBand->webBrowser2->Navigate(L"http://www.dnssec-validator.cz/"/*&varURL*/, &varEmpty, &varEmpty, &varEmpty, &varEmpty);
		//------------------------------------
		RepaintButton(BUTTON_INDEX,5);
		//------------------------------------
		break;
	}
}

//-------------------------------------------------------------------------
// Redraw of button bitmap when DNSSEC status was changed
//-------------------------------------------------------------------------
bool CKBToolBarCtrl::RepaintButton(int bindex, int iconindex){
	ATLTRACE("RepaintButton():\n");
	//delete of last button from toolbar
	if (!DeleteButton(bindex))
	return false;
	//set new parameters for nu button 
	TBBUTTON tbs;
		tbs.dwData = 0;
		tbs.fsState = TBSTATE_ENABLED;
		tbs.fsStyle = TBSTYLE_BUTTON;
		tbs.iBitmap = iconindex;
		tbs.idCommand = ID_BUTTON1;
		tbs.iString = 0;
	//insert of new button into toolbar
	if (!InsertButton(bindex,&tbs))
	return false;
  return true;
}
