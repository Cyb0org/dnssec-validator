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

CHyperLink m_link;
/*
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
*/
wchar_t* BUTTONTEXT = L"";
//-------------------------------------------------------------------
// Definition of toolbar style
//-------------------------------------------------------------------
const DWORD DEFAULT_TOOLBAR_STYLE = 
		 WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE |
		 TBSTYLE_FLAT |	TBSTYLE_TRANSPARENT  | BS_FLAT |	TBSTYLE_LIST | TBSTYLE_DROPDOWN	|			
		 CCS_TOP | CCS_NODIVIDER | CCS_NOPARENTALIGN | CCS_NORESIZE;

/////////////////////////////////////////////////////////////////////////////
// CKBToolBarCtrl
//CHyperLink m_link;

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
	ON_NOTIFY_REFLECT(TBN_DROPDOWN, &CKBToolBarCtrl::OnTbnDropDown)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CKBToolBarCtrl operations
/**************************************************************************/
// Default creation code, create of toolbar with one bitmap button 
/**************************************************************************/
bool CKBToolBarCtrl::Create(CRect rcClientParent, CWnd* pWndParent, CKBBarBand* pBand, HINSTANCE GHins) 
{
	//ATLTRACE("CreateToolbar():\n");
	if (!CToolBarCtrl::Create(DEFAULT_TOOLBAR_STYLE, rcClientParent, pWndParent, NULL))
		return false;	

	int res;
	// Generation of Bitmap List Index
	for (int i=0; i<BITMAP_NUMBER; i++) {
		res = AddBitmap(1, StatusBitmap[i]);
		if (res == -1)
		{
			DWORD dwError = ::GetLastError();
			return false;
		}//if
	}
	
	LANGID lang;
	lang = GetSystemDefaultLangID();
	if (lang==0x0405){
	// 0x0405 CZ
	// Generation of String List Index CZ
		for (int i=0; i<BITMAP_NUMBER+1; i++) res = AddStrings(stringtextCZ[i]);
	}
	// 0x0407 DE
	else if (lang==0x0407) {
		for (int i=0; i<BITMAP_NUMBER+1; i++) res = AddStrings(stringtextDE[i]);
	}
	else
	{
	// Generation of String List Index EN
	for (int i=0; i<BITMAP_NUMBER+1; i++) res = AddStrings(stringtextEN[i]);
	} // if

	// set button properties
	TBBUTTON tbs;
		tbs.dwData = 0;
		tbs.fsState = TBSTATE_ENABLED;
		tbs.fsStyle = BTNS_DROPDOWN;
		tbs.iBitmap = 0;
		tbs.idCommand = ID_BUTTON1;
		tbs.iString = 0;
	// add button into toolbar
	if (!AddButtons(1, &tbs))
		return false;
	CToolBarCtrl::SetExtendedStyle(TBSTYLE_EX_DRAWDDARROWS);
	// set handle on this window
	m_pBand = pBand;
	return true;
}

/**************************************************************************/
//I dont know, what is it or what to do it. May be message filter TRACE 
/**************************************************************************/
STDMETHODIMP CKBToolBarCtrl::TranslateAcceleratorIO(LPMSG pMsg)
{
	return S_FALSE;
}

/**************************************************************************/
// Command Message for popup menu click (arrows)
/**************************************************************************/
void CKBToolBarCtrl::OnTbnDropDown(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMTOOLBAR pNMTB = reinterpret_cast<LPNMTOOLBAR>(pNMHDR);

		_variant_t varEmpty;
	_variant_t varURL;
	switch (pNMTB->iItem) 	{
	case ID_BUTTON1:
		//ATLTRACE("ID_BUTTON1():\n");
		RECT rc;
		SendMessage(TB_GETRECT, ID_BUTTON1, (LPARAM)&rc);
		::MapWindowPoints(m_pBand->m_wndToolBar, HWND_DESKTOP, (LPPOINT)&rc, 2);
 
		 TPMPARAMS tpm;
         
         tpm.cbSize    = sizeof(TPMPARAMS);
         tpm.rcExclude = rc;
			//obtaining the current menu
			HMENU hMenuStatusBar = GetSubMenu(LoadMenu(GHins,MAKEINTRESOURCE(IDR_MENU_POPUP)), 0);
			//if available
			if(hMenuStatusBar) {
				//obtaining the element that has been chosen 
				int cmd = TrackPopupMenuEx(hMenuStatusBar, TPM_NONOTIFY|TPM_RETURNCMD|TPM_LEFTBUTTON|TPM_RIGHTALIGN, rc.left+142, rc.bottom, m_pBand->m_wndToolBar,  &tpm);			
				switch (cmd) {
					case ID_ENABLED : {
						break;
					}
					case ID_ABOUT : { 
						DialogBox(GHins, MAKEINTRESOURCE(IDD_DIALOG_MAIN_ABOUT), NULL , (DLGPROC)DialogProcAbout);
						break;
					}
					case ID_SET : { 
						DialogBox(GHins, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, (DLGPROC)DialogProcSettings);
						break;
					}
					case ID_HOME : { 
						m_pBand->webBrowser2->Navigate(L"https://labs.nic.cz/page/1031/", &varEmpty, &varEmpty, &varEmpty, &varEmpty);
						break;
					}
				}
			}
			break;
	}
}

/**************************************************************************/
// Command Message for popup menu click (Button)
/**************************************************************************/
void CKBToolBarCtrl::OnCommand()
{	//Save current massage from toolbar
	//ATLTRACE("OnCommandButton():\n");
	const MSG* pMsg = GetCurrentMessage();
	int nID = LOWORD(pMsg->wParam);
	_variant_t varEmpty;
	_variant_t varURL;
	//Button action - change URL in IE browser 
	switch (nID)
	{
	case ID_BUTTON1:
		//ATLTRACE("ID_BUTTON1():\n");
		RECT rc;
		// get coordinates of Button
		SendMessage(TB_GETRECT, ID_BUTTON1, (LPARAM)&rc);
		::MapWindowPoints(m_pBand->m_wndToolBar, HWND_DESKTOP, (LPPOINT)&rc, 2);
		// set new cooridnate for popupmenu
		 TPMPARAMS tpm;         
         tpm.cbSize    = sizeof(TPMPARAMS);
         tpm.rcExclude = rc;
			//obtaining the current menu
			HMENU hMenuStatusBar = GetSubMenu(LoadMenu(GHins,MAKEINTRESOURCE(IDR_MENU_POPUP)), 0);
			//if available
			if(hMenuStatusBar) {
				//obtaining the element that has been chosen 
				int cmd = TrackPopupMenuEx(hMenuStatusBar, TPM_NONOTIFY|TPM_RETURNCMD|TPM_LEFTBUTTON|TPM_RIGHTALIGN, rc.left+142, rc.bottom, m_pBand->m_wndToolBar,  &tpm);			
				switch (cmd) {
					case ID_ENABLED : {
						break;
					}
					case ID_ABOUT : { 
						// show dialog About
						DialogBox(GHins, MAKEINTRESOURCE(IDD_DIALOG_MAIN_ABOUT), NULL , (DLGPROC)DialogProcAbout);	
						break;
					}
					case ID_SET : { 
						// show dialog Settings
						DialogBox(GHins, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, (DLGPROC)DialogProcSettings);
						break;
					}
					case ID_HOME : { 
						// navigate to home page
						m_pBand->webBrowser2->Navigate(L"https://labs.nic.cz/page/1031/", &varEmpty, &varEmpty, &varEmpty, &varEmpty);					
						break;
					}
				}
			}
			break;
	}
}

/**************************************************************************/
// Redraw of button bitmap when DNSSEC status was changed
/**************************************************************************/
bool CKBToolBarCtrl::RepaintButton(int bindex, int iconindex){
	//ATLTRACE("RepaintButton():\n");
	//delete of last button from toolbar
	if (!DeleteButton(bindex))
	return false;
	//set new parameters for nu button 
	TBBUTTON tbs;
		tbs.dwData = 0;
		tbs.fsState = TBSTATE_ENABLED;
		tbs.fsStyle = BTNS_DROPDOWN;
		tbs.iBitmap = iconindex;
		tbs.idCommand = ID_BUTTON1;
		if (textkey) tbs.iString = iconindex;
		else {
			tbs.iString = 7;
			tbs.fsStyle = BTNS_AUTOSIZE | BTNS_DROPDOWN;
		}// if textkey
	//insert of new button into toolbar
	if (!InsertButton(bindex,&tbs))
	return false;
	// set button style arrows for popup menu
	CToolBarCtrl::SetExtendedStyle(TBSTYLE_EX_DRAWDDARROWS);
  return true;
}

/**************************************************************************/
// CallBack function for dialog Setting
/**************************************************************************/
LRESULT CKBToolBarCtrl::DialogProcSettings(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//ATLTRACE("DialogProcSettings\n");
	switch ( uMsg )
	{
	case WM_INITDIALOG:
        {
		//ATLTRACE("WM_INITDIALOG\n");
       
		//CZ.NIC 217.31.204.130 2001:1488:800:400::130 217.31.204.131 2001:1488:800:400::131
	   
		//OARC 149.20.64.20 2001:4f8:3:2bc:1::64:20 149.20.64.21 2001:4f8:3:2bc:1::64:21

		::SendDlgItemMessage(hwndDlg, IDC_COMBO, CB_INITSTORAGE, 2, 10);
		::SendDlgItemMessage(hwndDlg, IDC_COMBO, CB_INSERTSTRING, 0, (LPARAM)"CZ.NIC");
		::SendDlgItemMessage(hwndDlg, IDC_COMBO, CB_INSERTSTRING, 1, (LPARAM)"OARC");
		if (choice2) ::SendDlgItemMessage(hwndDlg, IDC_COMBO, CB_SETCURSEL, 1, 0);
		else ::SendDlgItemMessage(hwndDlg, IDC_COMBO, CB_SETCURSEL, 0, 0);
		::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), FALSE);
		::SendMessage(::GetDlgItem(hwndDlg, IDC_SHOWTEXT), BM_SETCHECK,  textkey ? BST_CHECKED : BST_UNCHECKED, 0);
		::SendMessage(::GetDlgItem(hwndDlg, IDC_TCP), BM_SETCHECK,  tcpudp ? BST_CHECKED : BST_UNCHECKED, 0);
		::SetWindowText(::GetDlgItem(hwndDlg,IDC_EDIT),dnssecseradr);
		::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), FALSE);			
		::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), FALSE);
		::SendMessage(::GetDlgItem(hwndDlg, IDC_DEBUG), BM_SETCHECK,  debugoutput ? BST_CHECKED : BST_UNCHECKED, 0);
		if (debugoutput_enable==0) ::EnableWindow(::GetDlgItem(hwndDlg,IDC_DEBUG), FALSE);
		else ::EnableWindow(::GetDlgItem(hwndDlg,IDC_DEBUG), TRUE);

		if (choice==2) {
			::CheckRadioButton(hwndDlg, IDC_R1, IDC_R3, IDC_R3);
			::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), TRUE);			
		}
		else if (choice==1){
			::CheckRadioButton(hwndDlg, IDC_R1, IDC_R3, IDC_R2);
			::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), TRUE);			
		}
		else {
			::CheckRadioButton(hwndDlg, IDC_R1, IDC_R3, IDC_R1);
		} // if choice
        break;
		}	
	
	case WM_COMMAND:
			switch ( LOWORD(wParam) )
			{
				//ATLTRACE("WM_COMMAND\n");
				case IDOK:
					{
							DWORD dwRet;
							HKEY hKey;
							DWORD dwVal;
							int msgboxID;
							// open DNSSEC Validator registry key if exists
							dwRet = RegOpenKeyEx(HKEY_USERS, HKU_REG_KEY, 0, KEY_ALL_ACCESS, &hKey);
							if (dwRet == ERROR_SUCCESS) {							   
							
								// save keytext setting into Register
								dwVal = (DWORD)::SendMessage(::GetDlgItem(hwndDlg, IDC_SHOWTEXT), BM_GETCHECK, 0, 0);
								dwRet = RegSetValueEx(hKey, "keytext", NULL, REG_DWORD, (CONST BYTE*)&dwVal, sizeof(dwVal));
								//if (dwRet != ERROR_SUCCESS)  //ATLTRACE("\nmam1\n");
								// save tcpudp DWORD into Register
								dwVal = (DWORD)::SendMessage(::GetDlgItem(hwndDlg, IDC_TCP), BM_GETCHECK, 0, 0);
								dwRet = RegSetValueEx(hKey, "tcpudp", NULL, REG_DWORD, (CONST BYTE*)&dwVal, sizeof(dwVal));

								// save debugoutput DWORD into Register
								if (debugoutput_enable!=0) {
									dwVal = (DWORD)::SendMessage(::GetDlgItem(hwndDlg, IDC_DEBUG), BM_GETCHECK, 0, 0);
									dwRet = RegSetValueEx(hKey, "debugoutput", NULL, REG_DWORD, (CONST BYTE*)&dwVal, sizeof(dwVal));
								}

		
								// save choice setting resolver into Register
								if (::IsDlgButtonChecked(hwndDlg, IDC_R1))
								    dwVal = 0;
								else if (::IsDlgButtonChecked(hwndDlg, IDC_R2))
								{	
									dwVal = 1;
									DWORD ch = ::SendMessage(::GetDlgItem(hwndDlg, IDC_COMBO), CB_GETCURSEL,  0 , 0);
									dwRet = RegSetValueEx(hKey, "choicedns", NULL, REG_DWORD, (CONST BYTE*)&ch, sizeof(ch));														
								}
								else if (::IsDlgButtonChecked(hwndDlg, IDC_R3))
								{
									dwVal = 2;									
									TCHAR chText[100];
									::GetDlgItemText(hwndDlg, IDC_EDIT, chText, 100);
									char* szVal=(char*)chText;
									
									if (ValidateIP(szVal)) dwRet = RegSetValueEx(hKey, "userip", NULL, REG_SZ, (CONST BYTE*)(LPCTSTR)szVal, strlen(szVal)+1);
									else msgboxID = MessageBoxW( NULL, (LPCWSTR)L"Invalid IPv4 format!\nThe IPv4 address is not stored.", (LPCWSTR)L"Invalid IPv4 format", MB_OK | MB_ICONERROR);
								}// id IsDlgButtonChecked
								dwRet = RegSetValueEx(hKey, "choice", NULL, REG_DWORD, (CONST BYTE*)&dwVal, sizeof(dwVal));								
							
								} //if dwRet							
								if (dwRet == ERROR_ACCESS_DENIED) {	
								msgboxID = MessageBoxW( NULL, (LPCWSTR)L"Access Denied!\nYou must be logged as Administartor.", (LPCWSTR)L"Access Denied", MB_OK | MB_ICONERROR);
								}
								RegCloseKey(hKey);																						
					EndDialog(hwndDlg, LOWORD(wParam));					
					break;
					}
				case IDCANCEL:
					EndDialog(hwndDlg, LOWORD(wParam));					
					break;
				case IDC_R2:
					{
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), FALSE);
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), TRUE);		
					}
					break;
				case IDC_R3:
					{
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), FALSE);
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), TRUE);
					}
					break;
				case IDC_R1:
					{					
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), FALSE);
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), FALSE);
					}
					break;
			}
			break;
	}
    
	return (INT_PTR)FALSE;
}

/**************************************************************************/
// CallBack function for dialog About
/**************************************************************************/
LRESULT CKBToolBarCtrl::DialogProcAbout(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//ATLTRACE("DialogProcAbout\n");
	switch ( uMsg )
	{
		
	case WM_INITDIALOG:
        {		
			m_link.ConvertStaticToHyperlink(hwndDlg, IDC_LINK, _T("https://labs.nic.cz/page/1031/"));
        break;
		}	
	
	case WM_COMMAND:
			switch ( LOWORD(wParam) )
			{
				//ATLTRACE("WM_COMMAND\n");
				case IDOK:
					EndDialog(hwndDlg, LOWORD(wParam));					
					break;
			}
			break;
	}
    
	return (INT_PTR)FALSE;
}

/**************************************************************************/
// Validation of IPv4
/**************************************************************************/
bool CKBToolBarCtrl::ValidateIP(char *ipadd)
{

	unsigned b1, b2, b3, b4;
	unsigned char c;

	if (sscanf_s(ipadd, "%3u.%3u.%3u.%3u%c", &b1, &b2, &b3, &b4, &c) != 4) return 0;
	if ((b1 | b2 | b3 | b4) > 255) return 0;
	if (strspn(ipadd, "0123456789.") < strlen(ipadd)) return 0;

	return 1;
}