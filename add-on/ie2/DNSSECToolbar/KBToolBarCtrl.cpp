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
#include "Windowsx.h"

CHyperLink m_link;
CKBBarBand* m_pBarBand;
LANGID lang;
wchar_t* BUTTONTEXT = L"";
int dx,dy=0;
short cache_del = 0;
//-------------------------------------------------------------------
// Definition of toolbar style
//-------------------------------------------------------------------
const DWORD DEFAULT_TOOLBAR_STYLE = 
		 WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE |
		 TBSTYLE_FLAT |	TBSTYLE_TRANSPARENT  | BS_FLAT |	TBSTYLE_LIST | TBSTYLE_DROPDOWN	|			
		 CCS_TOP | CCS_NODIVIDER | CCS_NOPARENTALIGN | CCS_NORESIZE;

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
	//if (debug) ATLTRACE("CreateToolbar():\n");
	if (!CToolBarCtrl::Create(DEFAULT_TOOLBAR_STYLE, rcClientParent, pWndParent, NULL))
		return false;	

	int res = 0;

	// Generation of Bitmap List Index
	for (int i=0; i<BITMAP_NUMBER; i++) {
		res = AddBitmap(1, StatusBitmap[i]);
		if (res == -1)
		{
			DWORD dwError = ::GetLastError();
			return false;
		}//if
	}

	//lang = GetSystemDefaultLangID();
	lang = GetUserDefaultLangID();
	
	if (lang==0x0405){
	// 0x0405 CZ
	// Generation of String List Index CZ
		for (int i=0; i<BITMAP_NUMBER+2; i++) res = AddStrings(stringtextCZ[i]);
	}
	// 0x0407 DE
	else if (lang==0x0407) {
		for (int i=0; i<BITMAP_NUMBER+2; i++) res = AddStrings(stringtextDE[i]);
	}
	else
	{
	// Generation of String List Index EN
		for (int i=0; i<BITMAP_NUMBER+2; i++) res = AddStrings(stringtextEN[i]);
	} // if

	// set button properties
	TBBUTTON tbs;
		tbs.dwData = 0;
		tbs.fsState = TBSTATE_ENABLED;
		tbs.fsStyle = BTNS_DROPDOWN;
		tbs.iBitmap = 0;
		tbs.idCommand = ID_BUTTON1;
		tbs.iString = BITMAP_NUMBER;
	// add button into toolbar
	if (!AddButtons(1, &tbs)) return false;

	if (tlsaenable == 1) {
		tbs.dwData = 0;
		tbs.fsState = TBSTATE_ENABLED;
		tbs.fsStyle = BTNS_DROPDOWN;
		tbs.iBitmap = 0;
		tbs.idCommand = ID_BUTTON2;
		tbs.iString = BITMAP_NUMBER+1;
		if (!AddButtons(1, &tbs)) return false;
	}

	CToolBarCtrl::SetExtendedStyle(TBSTYLE_EX_DRAWDDARROWS);
	// set handle on this window
	m_pBand = pBand;
			// set ICON instead BMP
	HICON hIcon;
	CImageList *pList = CKBToolBarCtrl::GetImageList();
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DNSSEC_ICON_INIT));
		pList->Replace(0, hIcon); // 
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DNSSEC_ICON_OFF));
		pList->Replace(1, hIcon); // 
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DNSSEC_ICON_ERROR));
		pList->Replace(2, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DNSSEC_ICON_ACTION));
		pList->Replace(3, hIcon); // 
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DNSSEC_ICON_NO));
		pList->Replace(4, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DNSSEC_ICON_VALID));
		pList->Replace(5, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DNSSEC_ICON_BOGUS));
		pList->Replace(6, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DNSSEC_ICON_IP));
		pList->Replace(7, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DNSSEC_ICON_ORANGE));
		pList->Replace(8, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_TLSA_ICON_INIT));
		pList->Replace(9, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_TLSA_ICON_OFF));
		pList->Replace(10, hIcon); // 
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_TLSA_ICON_ERROR));
		pList->Replace(11, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_TLSA_ICON_ACTION));
		pList->Replace(12, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_TLSA_ICON_NODNSSEC));
		pList->Replace(13, hIcon); // 
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_TLSA_ICON_VALID));
		pList->Replace(14, hIcon); // 
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_TLSA_ICON_INVALID));
		pList->Replace(15, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_TLSA_ICON_NOHTTPS));
		pList->Replace(16, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_TLSA_ICON_NO));
		pList->Replace(17, hIcon); //
		hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_TLSA_ICON_ORANGE));
		pList->Replace(18, hIcon); //
	CKBToolBarCtrl::SetImageList(pList);
	CKBToolBarCtrl::Invalidate();
	
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
	_variant_t vWindow;
	vWindow.bstrVal = (BSTR)("_blank");
			RECT rc;
					 TPMPARAMS tpm;
					 HMENU hMenuStatusBar;
	switch (pNMTB->iItem) 	{
	case ID_BUTTON1:
		if (debug) ATLTRACE("ID_BUTTON1():\n");	
		SendMessage(TB_GETRECT, ID_BUTTON1, (LPARAM)&rc);
		::MapWindowPoints(m_pBand->m_wndToolBar, HWND_DESKTOP, (LPPOINT)&rc, 2);

         tpm.cbSize    = sizeof(TPMPARAMS);
         tpm.rcExclude = rc;
		  //if (debug) ATLTRACE("PWProc: rcClient l: %d; b: %d; r: %d; t: %d\n", rc.left, rc.bottom, rc.right, rc.top);
			//obtaining the current menu
			hMenuStatusBar = GetSubMenu(LoadMenu(GHins,MAKEINTRESOURCE(IDR_MENU_POPUP)), 0);
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
						m_pBand->webBrowser2->Navigate(L"http://www.dnssec-validator.cz", &varEmpty, &vWindow , &varEmpty, &varEmpty);						
						break;
					}
				}
			}
		break;
			
	case ID_BUTTON2:
		if (debug) ATLTRACE("ID_BUTTON2():\n");

		SendMessage(TB_GETRECT, ID_BUTTON2, (LPARAM)&rc);
		::MapWindowPoints(m_pBand->m_wndToolBar, HWND_DESKTOP, (LPPOINT)&rc, 2);
         tpm.cbSize    = sizeof(TPMPARAMS);
         tpm.rcExclude = rc;
		  //if (debug) ATLTRACE("PWProc: rcClient l: %d; b: %d; r: %d; t: %d\n", rc.left, rc.bottom, rc.right, rc.top);
			//obtaining the current menu
			hMenuStatusBar = GetSubMenu(LoadMenu(GHins,MAKEINTRESOURCE(IDR_MENU_POPUP)), 0);
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
						m_pBand->webBrowser2->Navigate(L"http://www.dnssec-validator.cz", &varEmpty, &vWindow , &varEmpty, &varEmpty);						
						break;
					}
				}
			}
		break;
	}
}

/**************************************************************************/
// Wrong resolver
/**************************************************************************/
int CKBToolBarCtrl::WrongResolver()
{
		//HWND hwnd;
		int msgboxID;
		lang = GetUserDefaultLangID();
		if (lang==0x0405) msgboxID = MessageBoxW( NULL, (LPCWSTR)L"Aktuálnì nastavený resolver nepodporuje DNSSEC technologii. Prosím, zmìòte nastavení validátoru.\n\nChcete pøejít do nastavení?", (LPCWSTR)L"Upozornìní DNSSEC Validátoru", MB_YESNO |  MB_ICONWARNING);
		else if (lang==0x0407) msgboxID = MessageBoxW( NULL, (LPCWSTR)L"Der zur Zeit eingestellte Resolver unterstützt DNSSEC nicht. Ändern Sie bitte die Einstellungen des Resolvers.\n\nWollen Sie zu den Einstellungen weitergehen?", (LPCWSTR)L"Warnung DNSSEC Valiator", MB_YESNO |  MB_ICONWARNING);
		else msgboxID = MessageBoxW( NULL, (LPCWSTR)L"Current DNS server or resolver does not support DNSSEC technology. Please, change the validator settings.\n\nDo you want to proceed to settings?", (LPCWSTR)L"DNSSEC Valiadtor warning", MB_YESNO |  MB_ICONWARNING);
		
		wrong = false;
		switch (msgboxID) {

					case IDYES : {
						//::PostMessage(NULL, WM_CLOSE, 0, 0);
						DialogBox(GHins, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, (DLGPROC)DialogProcSettings);
						break;
					}
		
		}
	return msgboxID;
}

/**************************************************************************/
// Command Message for popup menu click (Button)
/**************************************************************************/
void CKBToolBarCtrl::OnCommand()
{	
	//if (debug) ATLTRACE("OnCommandButton():\n");
	const MSG* pMsg = GetCurrentMessage();
	int nID = LOWORD(pMsg->wParam);
	switch (nID)
	{
		case ID_BUTTON1:
		{
			RECT rc;
			RECT rc2;
			SendMessage(TB_GETRECT, ID_BUTTON1, (LPARAM)&rc);
			HWND handle=::FindWindow("IEFrame", NULL);
			//if (debug) ATLTRACE("Handle: %d\n", handle);
			::GetWindowRect(handle,&rc2);
			//if (debug) ATLTRACE("PWProc1: rcClient l: %d; b: %d; r: %d; t: %d\n", rc2.left, rc2.bottom, rc2.right, rc2.top);
			::MapWindowPoints(m_pBand->m_wndToolBar, HWND_DESKTOP, (LPPOINT)&rc, 2);
			//if (debug) ATLTRACE("PWProc2: rcClient l: %d; b: %d; r: %d; t: %d\n", rc.left, rc.bottom, rc.right, rc.top);
			int dialog_size = 336;
			LONG dei;
			dei = rc2.right - rc2.left;
			dei = dei / 2;
			dei = dei + rc2.left;
			//if (debug) ATLTRACE("Handle: %d\n", dei);
			if (rc.left < dei && (rc.left+dialog_size) < rc2.right) {
				dx = (int)rc.left;
				dy = (int)rc.bottom;
			}
			else {
				dx = (int)rc.left+TB_MIN_SIZE_X-15-dialog_size;
				dy = (int)rc.bottom;
			}
			//if (debug) ATLTRACE("PWProc3: rcClient l: %d; b: %d; r: %d; t: %d\n",dx, dy, rc.right, rc.top);
			if (keylogo==3 || keylogo==0) ;
			else DialogBox(GHins, MAKEINTRESOURCE(IDD_DIALOG_DNSSEC), NULL, (DLGPROC)DialogProcDnssec);
		break;
		}
			case ID_BUTTON2:
				{
			RECT rc;
			RECT rc2;
			SendMessage(TB_GETRECT, ID_BUTTON2, (LPARAM)&rc);
			HWND handle=::FindWindow("IEFrame", NULL);
			//if (debug) ATLTRACE("Handle: %d\n", handle);
			::GetWindowRect(handle,&rc2);
			//if (debug) ATLTRACE("PWProc1: rcClient l: %d; b: %d; r: %d; t: %d\n", rc2.left, rc2.bottom, rc2.right, rc2.top);
			::MapWindowPoints(m_pBand->m_wndToolBar, HWND_DESKTOP, (LPPOINT)&rc, 2);
			//if (debug) ATLTRACE("PWProc2: rcClient l: %d; b: %d; r: %d; t: %d\n", rc.left, rc.bottom, rc.right, rc.top);
			int dialog_size = 336;
			LONG dei;
			dei = rc2.right - rc2.left;
			dei = dei / 2;
			dei = dei + rc2.left;
			//if (debug) ATLTRACE("Handle: %d\n", dei);
			if (rc.left < dei && (rc.left+dialog_size) < rc2.right) {
				dx = (int)rc.left;
				dy = (int)rc.bottom;
			}
			else {
				dx = (int)rc.left+TB_MIN_SIZE_X-15-dialog_size;
				dy = (int)rc.bottom;
			}
			//if (debug) ATLTRACE("PWProc3: rcClient l: %d; b: %d; r: %d; t: %d\n",dx, dy, rc.right, rc.top);
			DialogBox(GHins, MAKEINTRESOURCE(IDD_DIALOG_TLSA), NULL, (DLGPROC)DialogProcTlsa);
		break;
		}



	}
}

/**************************************************************************/
// Redraw of button bitmap when DNSSEC status was changed
/**************************************************************************/
bool CKBToolBarCtrl::RepaintButtonDNSSEC(int bindex, int iconindex){
	if (debug) ATLTRACE("RepaintButtonDNSSEC(%d,%d):\n", bindex,iconindex);
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
			tbs.iString = BITMAP_NUMBER;
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
// Redraw of button bitmap when TLSA status was changed
/**************************************************************************/
bool CKBToolBarCtrl::RepaintButtonTLSA(int bindex, int iconindex){
	if (debug) ATLTRACE("RepaintButtonTLSA(%d,%d):\n",bindex,iconindex);
	//delete of last button from toolbar

	if (tlsaenable==1) {
		if (IsButtonHidden(ID_BUTTON2)) HideButton(ID_BUTTON2, FALSE);
		if (!DeleteButton(bindex)) return false;
	//set new parameters for nu button 
		TBBUTTON tbs;
		tbs.dwData = 0;
		tbs.fsState = TBSTATE_ENABLED;
		tbs.fsStyle = BTNS_DROPDOWN;
		tbs.iBitmap = iconindex;
		tbs.idCommand = ID_BUTTON2;
		if (textkey) tbs.iString = iconindex;
		else {
			tbs.iString = BITMAP_NUMBER+1;
			tbs.fsStyle = BTNS_AUTOSIZE | BTNS_DROPDOWN;
		}// if textkey
		//insert of new button into toolbar
		if (!InsertButton(bindex,&tbs)) return false;
	
		// set button style arrows for popup menu
		CToolBarCtrl::SetExtendedStyle(TBSTYLE_EX_DRAWDDARROWS);
	
	}
	else {
		if (!IsButtonHidden(ID_BUTTON2)) HideButton(ID_BUTTON2, TRUE);
		tlsaresult = DANE_OFF;
	}

  return true;
}

/**************************************************************************/
// CallBack function for dialog Setting
/**************************************************************************/
LRESULT CKBToolBarCtrl::DialogProcSettings(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//if (debug) ATLTRACE("DialogProcSettings\n");
	switch ( uMsg )
	{
	case WM_INITDIALOG:
        {
		//if (debug) ATLTRACE("WM_INITDIALOG\n");
		::SendDlgItemMessage(hwndDlg, IDC_COMBO, CB_INITSTORAGE, 2, 10);
		::SendDlgItemMessage(hwndDlg, IDC_COMBO, CB_INSERTSTRING, 0, (LPARAM)"CZ.NIC");
		::SendDlgItemMessage(hwndDlg, IDC_COMBO, CB_INSERTSTRING, 1, (LPARAM)"OARC");
		if (choice2) ::SendDlgItemMessage(hwndDlg, IDC_COMBO, CB_SETCURSEL, 1, 0);
		else ::SendDlgItemMessage(hwndDlg, IDC_COMBO, CB_SETCURSEL, 0, 0);
		::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), FALSE);
		//if (debug) ATLTRACE("%d", textkey);		
		::SetWindowText(::GetDlgItem(hwndDlg,IDC_EDIT),dnssecseradr);
		::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), FALSE);			
		::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), FALSE);		
		//if (debug) ATLTRACE("%d", choice);
		if (choice==2) {
			::CheckRadioButton(hwndDlg, IDC_R1, IDC_R4, IDC_R3);
			::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), TRUE);			
		}
		else if (choice==1){
			::CheckRadioButton(hwndDlg, IDC_R1, IDC_R4, IDC_R2);
			::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), TRUE);			
		}
		else if (choice==3) {
			::CheckRadioButton(hwndDlg, IDC_R1, IDC_R4, IDC_R4);
		} 
		else {
			::CheckRadioButton(hwndDlg, IDC_R1, IDC_R4, IDC_R1);
		} // if choice
		::SendMessage(::GetDlgItem(hwndDlg, IDC_DOM_ENABLE), BM_SETCHECK,  filteron ? BST_CHECKED : BST_UNCHECKED, 0);
		::SetWindowText(::GetDlgItem(hwndDlg,IDT_DOM_LIST),listtld);
		::EnableWindow(::GetDlgItem(hwndDlg,IDT_DOM_LIST), FALSE);
		if (filteron) ::EnableWindow(::GetDlgItem(hwndDlg,IDT_DOM_LIST), TRUE);
		::SendMessage(::GetDlgItem(hwndDlg, IDC_SHOWTEXT), BM_SETCHECK,  textkey ? BST_CHECKED : BST_UNCHECKED, 0);
		::SendMessage(::GetDlgItem(hwndDlg, IDC_ENABLETLSA), BM_SETCHECK,  tlsaenable ? BST_CHECKED : BST_UNCHECKED, 0);
        break;
		}	
	
	case WM_COMMAND:
		
		switch ( LOWORD(wParam) )
			{
				//if (debug) ATLTRACE("WM_COMMAND\n");
				case IDOK:
					{
							
				TCHAR szPath[MAX_PATH];
				if ( SUCCEEDED( SHGetFolderPath( NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, szPath ) ) )
					{
					PathAppend( szPath, INI_FILE_PATH);
								short dwVal;
								int msgboxID;
								// save keytext setting into Register
								dwVal = (short)::SendMessage(::GetDlgItem(hwndDlg, IDC_DOM_ENABLE), BM_GETCHECK, 0, 0);
								filteron = dwVal;
								if (dwVal) WritePrivateProfileString("DNSSEC", "filteron", "1", szPath);
								else WritePrivateProfileString("DNSSEC", "filteron", "0", szPath);

								dwVal = (short)::SendMessage(::GetDlgItem(hwndDlg, IDC_SHOWTEXT), BM_GETCHECK, 0, 0);
								textkey = dwVal;
								if (dwVal) WritePrivateProfileString("DNSSEC", "keytext", "1", szPath);
								else WritePrivateProfileString("DNSSEC", "keytext", "0", szPath);

								dwVal = (short)::SendMessage(::GetDlgItem(hwndDlg, IDC_ENABLETLSA), BM_GETCHECK, 0, 0);
								tlsaenable = dwVal;
								if (dwVal) WritePrivateProfileString("DNSSEC", "tlsaenable", "1", szPath);
								else {WritePrivateProfileString("DNSSEC", "tlsaenable", "0", szPath);																														
								}

								// save debugoutput DWORD into Register
								if (debugoutput_enable!=0) {
									dwVal = (short)::SendMessage(::GetDlgItem(hwndDlg, IDC_DEBUG), BM_GETCHECK, 0, 0);
									debugoutput = dwVal;
									if (dwVal) WritePrivateProfileString("DNSSEC", "debugoutput", "1", szPath);
									else WritePrivateProfileString("DNSSEC", "debugoutput", "0", szPath);									
								}





								// save choice setting resolver into Register
								if (::IsDlgButtonChecked(hwndDlg, IDC_R1))
								    dwVal = 0;
								else if (::IsDlgButtonChecked(hwndDlg, IDC_R2))
								{	
									short ch;
									dwVal = 1;
									ch =(short)::SendMessage(::GetDlgItem(hwndDlg, IDC_COMBO), CB_GETCURSEL,  0 , 0);
									choice2 = ch;
									if (ch) WritePrivateProfileString("DNSSEC", "choicedns", "1", szPath);
									else WritePrivateProfileString("DNSSEC", "choicedns", "0", szPath);														
								}
								else if (::IsDlgButtonChecked(hwndDlg, IDC_R3))
								{
									dwVal = 2;									
									TCHAR chText[IPADDR_MLEN];
									::GetDlgItemText(hwndDlg, IDC_EDIT, chText, IPADDR_MLEN);
									char* szVal=(char*)chText;
									
									if (!ValidateIP(szVal)) 									
									{ if (lang==0x0405) msgboxID = MessageBoxW( NULL, (LPCWSTR)L"Neplatná IPv4 nebo IPv6 adresa!\nNovì zadaná hodnota bude uložena ale nemusí být použita.\nProsím, zadejte znova správnou IP adresu resolveru.", (LPCWSTR)L"Neplatný formát zadané IP adresy", MB_OK | MB_ICONERROR);
										 else if (lang==0x0407) msgboxID = MessageBoxW( NULL, (LPCWSTR)L"Ungültige IPv4-Adresse oder IPv6-Adresse!\nDie neu angegebene wird gespeichert, muss aber nicht benutzt werden!\nGeben sie bitte eine richtige IP-Adresse eines Resolvers ein...", (LPCWSTR)L"Ungültige IP-Adresse", MB_OK | MB_ICONERROR);
										 else msgboxID = MessageBoxW( NULL, (LPCWSTR)L"Invalid IPv4 or IPv6 format!\nYour input will be stored, but invalid values will be skipped during resolving.\nPlease check and fix your input to avoid potential problems...", (LPCWSTR)L"Invalid IPv4 or Ipv6 format", MB_OK | MB_ICONERROR);
	
									} // if
									WritePrivateProfileString("DNSSEC", "userip", szVal, szPath);
								}// id IsDlgButtonChecked
								else dwVal = 3; 
								choice = dwVal;
								if (dwVal==2) WritePrivateProfileString("DNSSEC", "choice", "2", szPath);
								else if (dwVal==1) WritePrivateProfileString("DNSSEC", "choice", "1", szPath);
								else if (dwVal==3) WritePrivateProfileString("DNSSEC", "choice", "3", szPath);	
								else WritePrivateProfileString("DNSSEC", "choice", "0", szPath);

								

								
								TCHAR chTexttld[TLD_LIST_MLEN];
									::GetDlgItemText(hwndDlg, IDT_DOM_LIST, chTexttld, TLD_LIST_MLEN);
									char* szVal=(char*)chTexttld;
									WritePrivateProfileString("DNSSEC", "listtld", szVal, szPath);


								// save setting IPv4 IPv6 resolver
								/*
								if (::IsDlgButtonChecked(hwndDlg, IDC_IPv4)) WritePrivateProfileString("DNSSEC", "IPv4", "1", szPath);
								else WritePrivateProfileString("DNSSEC", "IPv4", "0", szPath);
								if (::IsDlgButtonChecked(hwndDlg, IDC_IPv6)) WritePrivateProfileString("DNSSEC", "IPv6", "1", szPath);
								else WritePrivateProfileString("DNSSEC", "IPv6", "0", szPath);
								if (::IsDlgButtonChecked(hwndDlg, IDC_IPv46)) 
									{
									WritePrivateProfileString("DNSSEC", "IPv4", "1", szPath);
									WritePrivateProfileString("DNSSEC", "IPv6", "1", szPath);
									}
								*/
							}
						/*
						    // code for windows register write
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
								//if (dwRet != ERROR_SUCCESS)  //if (debug) ATLTRACE("\nmam1\n");
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

								*/					
					EndDialog(hwndDlg, LOWORD(wParam));					
					// flush all cache items
					if (cache_del) {
						dnssec_validation_deinit(); dnssec_validation_init(); dane_validation_deinit(); dane_validation_init();						
						m_pBarBand->cache_delete_all();
					}
					cache_del = 0;
					
					break;
					}
				case IDCANCEL:
					EndDialog(hwndDlg, LOWORD(wParam));					
					break;
				case IDC_R2:
					{
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), FALSE);
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), TRUE);
					::SetWindowText(::GetDlgItem(hwndDlg,IDC_DNSSEC_R),"");
					cache_del = 1;
					}
					break;
				case IDC_R3:
					{
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), FALSE);
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), TRUE);
					::SetWindowText(::GetDlgItem(hwndDlg,IDC_DNSSEC_R),"");
					cache_del = 1;
					}
					break;
				case IDC_R1:
					{					
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), FALSE);
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), FALSE);
					::SetWindowText(::GetDlgItem(hwndDlg,IDC_DNSSEC_R),"");
					cache_del = 1;
					}
					break;
				case IDC_R4:
					{					
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_EDIT), FALSE);
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_COMBO), FALSE);
					::SetWindowText(::GetDlgItem(hwndDlg,IDC_DNSSEC_R),"");
					cache_del = 1;
					}
					break;
				case IDC_EDIT:
					{
					::SetWindowText(::GetDlgItem(hwndDlg,IDC_DNSSEC_R),"");
					cache_del = 1;		
					}
					break;
				case IDT_DOM_LIST:
					{
					//::SetWindowText(::GetDlgItem(hwndDlg,IDC_DNSSEC_R),"");
					//cache_del = 1;		
					}
					break;
				case IDC_DOM_ENABLE:
					{
						if(::SendMessage(::GetDlgItem(hwndDlg, IDC_DOM_ENABLE),BM_GETCHECK,0,0)==BST_CHECKED)
						::EnableWindow(::GetDlgItem(hwndDlg,IDT_DOM_LIST), TRUE);
						else ::EnableWindow(::GetDlgItem(hwndDlg,IDT_DOM_LIST), FALSE);
					//cache_del = 1;		
					}
					break;
				case IDC_COMBO:
					{
					::SetWindowText(::GetDlgItem(hwndDlg,IDC_DNSSEC_R),"");
					cache_del = 1;		
					}
					break;
				case IDC_IDDNSSEC:
					{					
					const int STR_BUF_S = 512;
					char strbuf[STR_BUF_S] = TEXT("");
					char* dnsip = "8.8.8.8";
					uint16_t options = 0;
					bool wrongip = false;
					char* ipvalidator;
					short resultipv4 = 0; //the DNSSEC validation result
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_IDDNSSEC), FALSE);
					LoadStringA(GHins, IDS_DNSSECTEST_RUN, strbuf, STR_BUF_S);
					::SetWindowText(::GetDlgItem(hwndDlg,IDC_DNSSEC_R),strbuf);					
				    dnssec_validation_deinit(); dnssec_validation_init(); dane_validation_deinit(); dane_validation_init();					
					options |= DNSSEC_FLAG_DEBUG;
					if (::IsDlgButtonChecked(hwndDlg, IDC_R4)) dnsip = "nofwd";
					else { options |= DNSSEC_FLAG_USEFWD;
						if (::IsDlgButtonChecked(hwndDlg, IDC_R1)) dnsip = "";
						else if (::IsDlgButtonChecked(hwndDlg, IDC_R3)) {
							TCHAR chText[100];
							::GetDlgItemText(hwndDlg, IDC_EDIT, chText, 100);
							char* szVal=(char*)chText;
							if (ValidateIP(szVal)) dnsip = szVal;
							else wrongip=true;
						}
					}
					options |= DNSSEC_FLAG_RESOLVIPV4;					
					//EnterCriticalSection(&cs);
					if (!wrongip) {
						//if (debug) ATLTRACE("\nTEST: www.nic.cz : %d : %s : 217.31.205.50\n", options, dnsip);
						resultipv4 = dnssec_validate("www.nic.cz", options, dnsip,  "217.31.205.50", &ipvalidator);
						//if (debug) ATLTRACE("TEST: www.nic.cz : %d : %s\n", resultipv4, ipvalidator);
						if (resultipv4==0) LoadStringA(GHins, IDS_DNSSECTEST_ERROR, strbuf, STR_BUF_S);
						else if ((resultipv4==4)) LoadStringA(GHins, IDS_DNSSECTEST_BOGUS, strbuf, STR_BUF_S);
						else LoadStringA(GHins, IDS_DNSSECTEST_OK, strbuf, STR_BUF_S);
					//LeaveCriticalSection(&cs);							
					} // if wrongip
					else {					
						LoadStringA(GHins, IDS_DNSSECTEST_IP, strbuf, STR_BUF_S);						
					}
					::SetWindowText(::GetDlgItem(hwndDlg,IDC_DNSSEC_R),strbuf);
					::EnableWindow(::GetDlgItem(hwndDlg,IDC_IDDNSSEC), TRUE);
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
	//if (debug) ATLTRACE("DialogProcAbout\n");
	switch ( uMsg )
	{
		
	case WM_INITDIALOG:
        {		
			// conver text to hyperlink
			m_link.ConvertStaticToHyperlink(hwndDlg, IDC_LINK, _T("http://www.dnssec-validator.cz"));
        break;
		}	
	
	case WM_COMMAND:
			switch ( LOWORD(wParam) )
			{
				//if (debug) ATLTRACE("WM_COMMAND\n");
				case IDOK:
					EndDialog(hwndDlg, LOWORD(wParam));					
					break;
			}
			break;
	}
    
	return (INT_PTR)FALSE;
}

/**************************************************************************/
// CallBack function for dialog DNSSEC
/**************************************************************************/
LRESULT CKBToolBarCtrl::DialogProcDnssec(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//if (debug) ATLTRACE("DialogProcAbout\n");
	switch ( uMsg )
	{
		
	case WM_INITDIALOG:
        {	
			const int STR_BUF_S = 512;
			char strbuf[STR_BUF_S] = TEXT("");
			char strbuf2[STR_BUF_S*2] = TEXT("");

			// set popup window coordinates
			::SetWindowPos(hwndDlg,NULL,dx,dy,0,0,SWP_NOSIZE);
			::SendMessage(::GetDlgItem(hwndDlg, IDOK), BST_UNCHECKED, NULL, NULL);

			// print domain name 
			::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST1),paneldomainname);

			// load and print titletext from resources
			LoadStringA(GHins, paneltitle, strbuf, STR_BUF_S);
			::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST2),strbuf);

			LoadStringA(GHins, panelpredonain, strbuf, STR_BUF_S);
			strncat_s(strbuf2, strbuf, STR_BUF_S*2);
			strncat_s(strbuf2, TEXT(" "), 1);
			strncat_s(strbuf2, paneldomainname, strlen(paneldomainname));
			strncat_s(strbuf2, TEXT(" "), 1);
			LoadStringA(GHins, panelpostdomain, strbuf, STR_BUF_S);
			strncat_s(strbuf2, strbuf, STR_BUF_S*2);
			::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST3),strbuf2);			

			// load and print posttext from resources
			//LoadStringA(GHins, panelpostdomain, strbuf, STR_BUF_S);
			//::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST4),strbuf);

			// load and print addtext from resources
			//if (debug) ATLTRACE("DialogProcAbout %i\n",keylogo);

			// set font for texts
			HFONT hFont ;
			LOGFONT lfFont;
			memset(&lfFont, 0x00, sizeof(lfFont));
			memcpy(lfFont.lfFaceName, TEXT("Arial"), 24);
			
			lfFont.lfHeight   = 15;
			lfFont.lfWeight   = FW_BOLD;
			lfFont.lfCharSet  = ANSI_CHARSET;
			lfFont.lfOutPrecision = OUT_DEFAULT_PRECIS;
			lfFont.lfClipPrecision = CLIP_DEFAULT_PRECIS;
			lfFont.lfQuality  = DEFAULT_QUALITY;
			hFont = CreateFontIndirect (&lfFont);
			::SendMessage(::GetDlgItem(hwndDlg, IDC_ST1), WM_SETFONT, (int)hFont, MAKELONG( TRUE, 0 ) );
			
			lfFont.lfHeight   = 18;
			lfFont.lfWeight   = FW_BOLD;
			hFont = CreateFontIndirect (&lfFont);
			::SendMessage(::GetDlgItem(hwndDlg, IDC_ST2), WM_SETFONT, (int)hFont, MAKELONG( TRUE, 0 ) );
			// set bold font for button text
			::SendMessage(::GetDlgItem(hwndDlg, IDOK), WM_SETFONT, (int)hFont, MAKELONG( TRUE, 0 ) );
			
			lfFont.lfHeight   = 14;
			lfFont.lfWeight   = FW_NORMAL;
			hFont = CreateFontIndirect (&lfFont);
			::SendMessage(::GetDlgItem(hwndDlg, IDC_ST3), WM_SETFONT, (int)hFont, MAKELONG( TRUE, 0 ) );
			::SendMessage(::GetDlgItem(hwndDlg, IDC_ST4), WM_SETFONT, (int)hFont, MAKELONG( TRUE, 0 ) );
			
			// load ico bitmap from resources
			HICON hicon = (HICON)LoadImage(GHins,MAKEINTRESOURCE(keylogo2), IMAGE_ICON,0,0,0);
			// set icon in popup window
			::SendMessage(::GetDlgItem(hwndDlg, IDC_ST6), STM_SETICON, (WPARAM)hicon, (LPARAM)NULL);
	
        break;
		}	
	case WM_COMMAND:
			switch ( LOWORD(wParam) )
			{
				case IDOK:
					EndDialog(hwndDlg, LOWORD(wParam));					
					break;
				case IDC_ST4:
			::ShowWindow(::GetDlgItem(hwndDlg, IDC_ST4), SW_HIDE);
			const int STR_BUF_S = 512;
			char strbuf[STR_BUF_S] = TEXT("");
			int mlength;
			short popupheight;
				//if (debug) ATLTRACE("sfdfsdf");	
				LoadStringA(GHins, paneltext, strbuf, STR_BUF_S);
				mlength = strlen(strbuf); 
				//if (debug) ATLTRACE("\n%d\n",mlength);

			if (res == 3) {
				if (mlength < 240) popupheight = 200;
				else if (mlength < 270) popupheight = 220;
				else popupheight = 250;
				::SetWindowPos(::GetDlgItem(hwndDlg,IDC_ST5),NULL,0,0,300,popupheight-130,SWP_NOMOVE);
				::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST5),strbuf);
				m_link.ConvertStaticToHyperlink(hwndDlg, IDC_LINK, _T("http://www.dnssec-validator.cz"));
				// resize popup window if IP message was set				
				
				popupheight=popupheight+70;
				const int STR_BUF_S = 512;
				char strbufb[STR_BUF_S] = TEXT("");
				char strbufv[STR_BUF_S] = TEXT("");
				strcpy_s(strbufb, ipbrowser4);
				strncat_s(strbufb, TEXT(" "), 1);
				strncat_s(strbufb, ipbrowser6, strlen(ipbrowser6));
				strcpy_s(strbufv, ipvalidator4);
				strncat_s(strbufv, ipvalidator6, strlen(ipvalidator6));		
				::SetWindowPos(::GetDlgItem(hwndDlg,IDC_STIPBH),NULL,15,popupheight-85,0,0,SWP_NOSIZE);
				::SetWindowText(::GetDlgItem(hwndDlg,IDC_STIPB),strbufb);				
				::SetWindowPos(::GetDlgItem(hwndDlg,IDC_STIPB),NULL,15,popupheight-70,0,0,SWP_NOSIZE);
				::SetWindowPos(::GetDlgItem(hwndDlg,IDC_STIPVH),NULL,15,popupheight-50,0,0,SWP_NOSIZE);
				::SetWindowText(::GetDlgItem(hwndDlg,IDC_STIPV),strbufv);
				::SetWindowPos(::GetDlgItem(hwndDlg,IDC_STIPV),NULL,15,popupheight-35,0,0,SWP_NOSIZE);
				::SetWindowPos(::GetDlgItem(hwndDlg,IDC_LINK),NULL,15,popupheight-5,0,0,SWP_NOSIZE);
				::SetWindowPos(hwndDlg,NULL,0,0,336,popupheight+25,SWP_NOMOVE);
			}
			else
			{
			::ShowWindow(::GetDlgItem(hwndDlg, IDC_STIPB), SW_HIDE);
			::ShowWindow(::GetDlgItem(hwndDlg, IDC_STIPV), SW_HIDE);
			::ShowWindow(::GetDlgItem(hwndDlg, IDC_STIPBH), SW_HIDE);
			::ShowWindow(::GetDlgItem(hwndDlg, IDC_STIPVH), SW_HIDE);
				if (mlength < 240) popupheight = 200;
				else if (mlength < 270) popupheight = 220;
				else popupheight = 250;
				::SetWindowPos(::GetDlgItem(hwndDlg,IDC_ST5),NULL,0,0,300,popupheight-130,SWP_NOMOVE);
				::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST5),strbuf);
				m_link.ConvertStaticToHyperlink(hwndDlg, IDC_LINK, _T("http://www.dnssec-validator.cz"));
				// resize popup window if IP message was set
				::SetWindowPos(::GetDlgItem(hwndDlg,IDC_LINK),NULL,15,popupheight-30,0,0,SWP_NOSIZE);
				::SetWindowPos(hwndDlg,NULL,0,0,336,popupheight,SWP_NOMOVE);
			}
					break;
			}
			break;
    case WM_LBUTTONDOWN:
			switch ( LOWORD(wParam) )
			{
				case MK_LBUTTON:
					EndDialog(hwndDlg, LOWORD(wParam));					
					break;
			}
			break;
	}    
	return (INT_PTR)FALSE;
}

/**************************************************************************/
// CallBack function for dialog TLSA
/**************************************************************************/
LRESULT CKBToolBarCtrl::DialogProcTlsa(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//if (debug) ATLTRACE("DialogProcAbout\n");
	switch ( uMsg )
	{
		
	case WM_INITDIALOG:
        {	
			const int STR_BUF_S = 512;
			char strbuf[STR_BUF_S] = TEXT("");
			char strbuf2[STR_BUF_S*2] = TEXT("");

			// set popup window coordinates
			::SetWindowPos(hwndDlg,NULL,dx,dy,0,0,SWP_NOSIZE);
			::SendMessage(::GetDlgItem(hwndDlg, IDOK), BST_UNCHECKED, NULL, NULL);

			// print domain name 
			if (debug) ATLTRACE("TLSA Panel Title: %s\n", tlsapaneldomainname);
			::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST1_TLSA),tlsapaneldomainname);

			// load and print titletext from resources
			LoadStringA(GHins, paneltitletlsa, strbuf, STR_BUF_S);
			::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST2_TLSA),strbuf);

			LoadStringA(GHins, paneltextmain, strbuf2, STR_BUF_S);
			::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST3_TLSA),strbuf2);			

			// load and print posttext from resources
			//LoadStringA(GHins, panelpostdomain, strbuf, STR_BUF_S);
			//::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST4),strbuf);

			// load and print addtext from resources
			//if (debug) ATLTRACE("DialogProcAbout %i\n",keylogo);

			// set font for texts
			HFONT hFont ;
			LOGFONT lfFont;
			memset(&lfFont, 0x00, sizeof(lfFont));
			memcpy(lfFont.lfFaceName, TEXT("Arial"), 24);
			
			lfFont.lfHeight   = 15;
			lfFont.lfWeight   = FW_BOLD;
			lfFont.lfCharSet  = ANSI_CHARSET;
			lfFont.lfOutPrecision = OUT_DEFAULT_PRECIS;
			lfFont.lfClipPrecision = CLIP_DEFAULT_PRECIS;
			lfFont.lfQuality  = DEFAULT_QUALITY;
			hFont = CreateFontIndirect (&lfFont);
			::SendMessage(::GetDlgItem(hwndDlg, IDC_ST1_TLSA), WM_SETFONT, (int)hFont, MAKELONG( TRUE, 0 ) );
			
			lfFont.lfHeight   = 18;
			lfFont.lfWeight   = FW_BOLD;
			hFont = CreateFontIndirect (&lfFont);
			::SendMessage(::GetDlgItem(hwndDlg, IDC_ST2_TLSA), WM_SETFONT, (int)hFont, MAKELONG( TRUE, 0 ) );
			// set bold font for button text
			::SendMessage(::GetDlgItem(hwndDlg, IDOK), WM_SETFONT, (int)hFont, MAKELONG( TRUE, 0 ) );
			
			lfFont.lfHeight   = 14;
			lfFont.lfWeight   = FW_NORMAL;
			hFont = CreateFontIndirect (&lfFont);
			::SendMessage(::GetDlgItem(hwndDlg, IDC_ST3_TLSA), WM_SETFONT, (int)hFont, MAKELONG( TRUE, 0 ) );
			::SendMessage(::GetDlgItem(hwndDlg, IDC_ST4_TLSA), WM_SETFONT, (int)hFont, MAKELONG( TRUE, 0 ) );
			
			// load ico bitmap from resources
			HICON hicon = (HICON)LoadImage(GHins,MAKEINTRESOURCE(tlsaiconres), IMAGE_ICON,0,0,0);
			// set icon in popup window
			::SendMessage(::GetDlgItem(hwndDlg, IDC_ST6_TLSA), STM_SETICON, (WPARAM)hicon, (LPARAM)NULL);
	
        break;
		}	
	case WM_COMMAND:
			switch ( LOWORD(wParam) )
			{
				case IDOK:
					EndDialog(hwndDlg, LOWORD(wParam));					
					break;
				case IDC_ST4_TLSA:
			::ShowWindow(::GetDlgItem(hwndDlg, IDC_ST4_TLSA), SW_HIDE);
			const int STR_BUF_S = 512;
			char strbuf[STR_BUF_S] = TEXT("");
			int mlength;
			short popupheight;
				//if (debug) ATLTRACE("sfdfsdf");	
				LoadStringA(GHins, paneltextadd, strbuf, STR_BUF_S);
				mlength = strlen(strbuf); 
				//if (debug) ATLTRACE("\n%d\n",mlength);
	
			::ShowWindow(::GetDlgItem(hwndDlg, IDC_STIPB_TLSA), SW_HIDE);
			::ShowWindow(::GetDlgItem(hwndDlg, IDC_STIPV_TLSA), SW_HIDE);
			::ShowWindow(::GetDlgItem(hwndDlg, IDC_STIPBH_TLSA), SW_HIDE);
			::ShowWindow(::GetDlgItem(hwndDlg, IDC_STIPVH_TLSA), SW_HIDE);
				if (mlength < 240) popupheight = 200;
				else if (mlength < 270) popupheight = 220;
				else popupheight = 250;
				::SetWindowPos(::GetDlgItem(hwndDlg,IDC_ST5_TLSA),NULL,0,0,300,popupheight-130,SWP_NOMOVE);
				::SetWindowText(::GetDlgItem(hwndDlg,IDC_ST5_TLSA),strbuf);
				m_link.ConvertStaticToHyperlink(hwndDlg, IDC_LINK, _T("http://www.dnssec-validator.cz"));
				// resize popup window if IP message was set
				::SetWindowPos(::GetDlgItem(hwndDlg,IDC_LINK),NULL,15,popupheight-30,0,0,SWP_NOSIZE);
				::SetWindowPos(hwndDlg,NULL,0,0,336,popupheight,SWP_NOMOVE);
			
					break;
			}
			break;
    case WM_LBUTTONDOWN:
			switch ( LOWORD(wParam) )
			{
				case MK_LBUTTON:
					EndDialog(hwndDlg, LOWORD(wParam));					
					break;
			}
			break;
	}    
	return (INT_PTR)FALSE;
}

/**************************************************************************/
// Test on IPv4 or IPv6 
/**************************************************************************/
bool CKBToolBarCtrl::isip6(char *ipadd){

	char tmp[50];
	char * pch;
	strcpy_s(tmp, ipadd);
    if (strcmp(tmp,"")==0) return 0;
	pch=strchr(tmp,':');
	if (pch!=NULL) return 1;
	else return 0;
}


/**************************************************************************/
// Validation of IPv4 @port-number
/**************************************************************************/
bool CKBToolBarCtrl::ValidateIP4(char *ipadd)
{
	unsigned b1, b2, b3, b4, port = 0;
	int rc;
	unsigned char c;
	rc = sscanf_s(ipadd, "%3u.%3u.%3u.%3u@%u%c", &b1, &b2, &b3, &b4, &port, &c);
	if (rc != 4 && rc != 5) return 0;
	if ((b1 | b2 | b3 | b4) > 255 || port > 65535) return 0;
	if (strspn(ipadd, "0123456789.@") < strlen(ipadd)) return 0;
	return 1;
}


/**************************************************************************/
// Simple validation of IPv6
/**************************************************************************/
bool CKBToolBarCtrl::ValidateIP6(char *ipadd)
{
	char tmp[50];
	strcpy_s(tmp, ipadd);

	if (strlen(tmp) < 3) return 0;
	if (strlen(tmp) > 48) return 0;
	if (strspn(ipadd, "0123456789:@") < strlen(ipadd)) return 0;
	return 1;
}

/**************************************************************************/
// Validation of IPv4, Validation of IPv6
/**************************************************************************/
// Validate of IPv4 and IPv6 addresses
// return 1 if all addresses are valid else 0
bool CKBToolBarCtrl::ValidateIP(char *ip)
{
	const char delimiters[] = " ";
    char *token;
    bool  is = false;
	int i;
	char* context	= NULL;
	char ipadd[100];
	int retval = 0;
	if (ip==NULL) return 0;
	if ((ip!=NULL) && (*ip=='\0')) return 0;
	strcpy_s(ipadd, ip);
    i = 1;
	if ((strcmp ((const char*)ipadd,"") != 0) || (strcmp ((const char*)ipadd," ") != 0))
      {
        token = strtok_s(ipadd, delimiters, &context);
        if (token==NULL) return 1;
        if (isip6(token)) is = ValidateIP6(token);
		else is = ValidateIP4(token);
        if (!is) return 0;
        while (token != NULL) {                    
            i++;
			token = strtok_s(NULL, delimiters,&context);
			if (token != NULL) {
				if (isip6(token)) is = ValidateIP6(token);
					else is = ValidateIP4(token);			
			}
        if (!is) return 0;                 
        }
        return 1;        
     }
   return 0;
}