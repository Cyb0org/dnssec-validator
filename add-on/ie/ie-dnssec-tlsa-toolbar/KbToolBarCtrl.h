/* ***** BEGIN LICENSE BLOCK *****
Copyright 2014 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator Add-on 2.x.

DNSSEC Validator Add-on 2.x is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator Add-on 2.x is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator Add-on 2.x.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

#pragma once

const int BITMAP_NUMBER = 19;

const int StatusBitmap[BITMAP_NUMBER] = {IDI_BMP_INIT0, IDI_BMP_INIT1, IDI_BMP_INIT2, IDI_BMP_INIT3, IDI_BMP_INIT4,
			IDI_BMP_INIT5, IDI_BMP_INIT6, IDI_BMP_INIT7, IDI_BMP_INIT8, IDI_BMP_INIT9, IDI_BMP_INIT10, IDI_BMP_INIT11,
			IDI_BMP_INIT12, IDI_BMP_INIT13, IDI_BMP_INIT14, IDI_BMP_INIT15, IDI_BMP_INIT16, IDI_BMP_INIT17, IDI_BMP_INIT18
};

const LPCTSTR stringtextCZ[BITMAP_NUMBER+2] = {_T("& DNSSEC Valid·tor\0") /*0*/, _T("& NeovÏ¯eno DNSSEC\0") /*1*/,
	_T("& Stav DNSSEC nezn·m˝\0") /*2*/, _T("& Zjiöùov·nÌ DNSSEC zabezpeËenÌ\0") /*3*/,  _T("& NezabezpeËeno DNSSEC\0") /*4*/, 
	_T("& ZabezpeËeno DNSSEC\0") /*5*/, _T("& Neplatn˝ DNSSEC podpis\0") /*6*/, _T("& ZabezpeËeno DNSSEC\0") /*7*/,
	_T("& NeovÏ¯eno DNSSEC\0") /*8*/, _T("& TLSA Valid·tor\0") /*9*/, _T("& TLSA validace vypnuta\0") /*10*/,
	_T("& Stav TLSA nezn·m˝\0") /*11*/, _T("& ProbÌh· validace TLSA\0") /*12*/,  _T("& NezabezpeËeno DNSSEC\0") /*13*/, 
	_T("& Certifik·t odpovÌd· TLSA\0") /*14*/, _T("& Certifik·t neodpovÌd· TLSA\0") /*15*/, _T("& NenÌ HTTPS spojenÌ\0") /*16*/,
	_T("& Neexistuje TLSA z·znam\0") /*17*/, _T("& Neplatn˝ DNSSEC podpis\0") /*18*/, _T("& DNSSEC\0") /*19*/, _T("& TLSA\0") /*20*/};

const LPCTSTR stringtextEN[BITMAP_NUMBER+2] = {_T("& DNSSEC Validator\0") /*0*/, _T("& Not verified by DNSSEC\0") /*1*/,
	_T("& DNSSEC status unknown\0") /*2*/, _T("& Retrieving DNSSEC status\0") /*3*/,  _T("& Not secured by DNSSEC\0") /*4*/, 
	_T("& Secured by DNSSEC\0") /*5*/, _T("& Bogus DNSSEC signature\0") /*6*/, _T("& Secured by DNSSEC\0") /*7*/,
	_T("& Not verified by DNSSEC\0") /*8*/, _T("& TLSA Validator\0") /*9*/, _T("& TLSA validation disabled\0") /*10*/,
	_T("& TLSA status unknown\0") /*11*/, _T("& TLSA validation in progress\0") /*12*/,  _T("& Not secured by DNSSEC\0") /*13*/, 
	_T("& Certificate corresponds to TLSA\0") /*14*/, _T("& Certificate doesn't correspond to TLSA\0") /*15*/, _T("& No HTTPS connection\0") /*16*/,
	_T("& TLSA record does not exist\0") /*17*/, _T("& Bogus DNSSEC signature\0") /*18*/, _T("& DNSSEC\0") /*19*/, _T("& TLSA\0") /*20*/};

const LPCTSTR stringtextDE[BITMAP_NUMBER+2] = {_T("& DNSSEC-Validator\0") /*0*/, _T("& Nicht durch DNSSEC gepr¸ft\0") /*1*/,
	_T("& DNSSEC-Zustand unbekannt\0") /*2*/, _T("& Erwerbung des DNSSEC-Zustandes\0") /*3*/,  _T("& Nicht durch DNSSEC gesichert\0") /*4*/, 
	_T("& Gesichert durch DNSSEC\0") /*5*/, _T("& Ung¸ltige DNSSEC-Signatur\0") /*6*/, _T("& Gesichert durch DNSSEC\0") /*7*/,
	_T("& Nicht durch DNSSEC gepr¸ft\0") /*8*/, _T("& TLSA-Validator\0") /*9*/, _T("& TLSA Validierung ausgeschaltet\0") /*10*/,
	_T("& TLSA Status unbekannt\0") /*11*/, _T("& TLSA Validierung wird durchgef¸hrt\0") /*12*/,  _T("& Nicht durch DNSSEC gesichert\0") /*13*/, 
	_T("& Zertifikat entspricht TLSA\0") /*14*/, _T("& Zertifikat entspricht nicht TLSA\0") /*15*/, _T("& Keine HTTPS Verbindung\0") /*16*/,
	_T("& Kein TLSA Eintrag vorhanden\0") /*17*/, _T("& Ung¸ltige DNSSEC Signatur\0") /*18*/, _T("& DNSSEC\0") /*19*/, _T("& TLSA\0") /*20*/};

const LPCTSTR stringtextPL[BITMAP_NUMBER+2] = {_T("& DNSSEC Validator\0") /*0*/, _T("& Nie zweryfikowane przez DNSSEC\0") /*1*/,
	_T("& Stan DNSSEC nieznany\0") /*2*/, _T("& Sprawdzanie stanu DNSSEC\0") /*3*/,  _T("& Niezabezpieczona przez DNSSEC\0") /*4*/, 
	_T("& Zabezpieczona przez DNSSEC\0") /*5*/, _T("& Fa≥szywy podpis DNSSEC\0") /*6*/, _T("& Zabezpieczona przez DNSSEC\0") /*7*/,
	_T("& Nie zweryfikowane przez DNSSEC\0") /*8*/, _T("& TLSA Validator\0") /*9*/, _T("& Walidacja TLSA wy≥πczona\0") /*10*/,
	_T("& Stan TLSA nieznany\0") /*11*/, _T("& Sprawdzanie stanu TLSA\0") /*12*/,  _T("& Niezabezpieczona przez DNSSEC\0") /*13*/, 
	_T("& Certyfikat odpowiada TLSA\0") /*14*/, _T("& Walidacja TLSA nie powiod≥a siÍ\0") /*15*/, _T("& Brak po≥πczeÒ HTTPS\0") /*16*/,
	_T("& Nieobecny rekord TLSA\0") /*17*/, _T("& Fa≥szywy podpis DNSSEC\0") /*18*/, _T("& DNSSEC\0") /*19*/, _T("& TLSA\0") /*20*/};

class CDNSSECToolBarBand;

/////////////////////////////////////////////////////////////////////////////
// CKBToolBarCtrl window
class CKBToolBarCtrl : public CToolBarCtrl
{
// Construction
public:
	CKBToolBarCtrl();
	BEGIN_MSG_MAP(CToolBarCtrl)
	END_MSG_MAP()

// Attributes
public:
	CDNSSECToolBarBand* m_pBand;

// Operations
public:
	bool Create(CRect rcClientParent, CWnd* pWndParent, CDNSSECToolBarBand* pBand, HINSTANCE GHins);
	bool RepaintButtonDNSSEC(int bindex, int iconindex);
	bool RepaintButtonTLSA(int bindex, int iconindex);
	int WrongResolver(void);
	static LRESULT CALLBACK DialogProcAbout(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static LRESULT CALLBACK DialogProcDnssec(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static LRESULT CALLBACK DialogProcTlsa(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static LRESULT CALLBACK DialogProcSettings(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    STDMETHOD(TranslateAcceleratorIO)(LPMSG pMsg);
	static bool CKBToolBarCtrl::ValidateIP(char *ipadd);
	static bool CKBToolBarCtrl::isip6(char *ipadd);
	static bool CKBToolBarCtrl::ValidateIP4(char *ipadd);
	static bool CKBToolBarCtrl::ValidateIP6(char *ipadd);
	void OnTbnDropDown(NMHDR *pNMHDR, LRESULT *pResult);
	void OnTbnDropDown2(NMHDR *pNMHDR, LRESULT *pResult);
	virtual ~CKBToolBarCtrl();

protected:
	afx_msg void OnCommand();
	DECLARE_MESSAGE_MAP()
};