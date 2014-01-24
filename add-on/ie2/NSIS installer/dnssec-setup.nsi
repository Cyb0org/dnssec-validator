# The NSIS (http://nsis.sourceforge.net) install script.
# This script is BSD licensed.
SetCompressor /solid /final lzma

!include LogicLib.nsh
!include MUI2.nsh
!include "FileFunc.nsh"

!define VERSION "2.1.0"
!define QUADVERSION "2.1.0.1"
!define guid '{669695BC-A811-4A9D-8CDF-BA8C795F261C}'
!define PROGRAM_NAME "DNSSEC-TLSA Validator"
!define PROGRAM_NAME_OLD "DNSSEC Validator 2.0"

outFile "IE-dnssec-tlsa_validator-${VERSION}-windows.exe"
Name "DNSSEC/TLSA Validator ${VERSION}"

# default install directory
installDir "$PROGRAMFILES\CZ.NIC\${PROGRAM_NAME}"
installDirRegKey HKLM "Software\${PROGRAM_NAME}" "InstallLocation"
RequestExecutionLevel admin
#give credits to Nullsoft: BrandingText ""
VIAddVersionKey "ProductName" "DNSSEC/TLSA Validator ${VERSION}"
VIAddVersionKey "CompanyName" "CZ.NIC Labs"
VIAddVersionKey "FileDescription" "(un)install the DNSSEC/TLSA Validator ${VERSION} for IE"
VIAddVersionKey "LegalCopyright" "Copyright 2013, CZ.NIC Labs"
VIAddVersionKey "FileVersion" "${QUADVERSION}"
VIAddVersionKey "ProductVersion" "${QUADVERSION}"
VIProductVersion "${QUADVERSION}"

# Global Variables
Var StartMenuFolder

# use ReserveFile for files required before actual installation
# makes the installer start faster
#ReserveFile "System.dll"
#ReserveFile "NsExec.dll"

!define MUI_ICON "key.ico"
!define MUI_UNICON "key.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "setup_top.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "setup_left.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "setup_left.bmp"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_TITLE_3LINES
;!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of Internet Explorer DNSSEC/TLSA Validator ${VERSION} add-on.$\r$\n$\nNote: It is recommended to close all running Internet Explorer windows before proceeding with the installation of the add-on.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "../../../Copying"
!insertmacro MUI_PAGE_DIRECTORY

!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKLM"
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\${PROGRAM_NAME}"
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"
!define MUI_STARTMENUPAGE_DEFAULTFOLDER "CZ.NIC\${PROGRAM_NAME}"
!insertmacro MUI_PAGE_STARTMENU DNSSECStartMenu $StartMenuFolder

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Czech"
!insertmacro MUI_LANGUAGE "German"

section "-hidden.postinstall"
	# copy files
	setOutPath $INSTDIR
	File ".\DNSSECcore-windows-x86.dll"
	File ".\DANEcore-windows-x86.dll"
	File ".\IEdnssec.dll"
	File ".\key.ico"
	File ".\RegPlugin.bat"
	File ".\UnRegPlugin.bat"
  
	# store installation folder
	WriteRegStr HKLM "Software\${PROGRAM_NAME}" "InstallLocation" "$INSTDIR"
	Delete "$LOCALAPPDATA\CZ.NIC\${PROGRAM_NAME}\dnssec.ini"
	# register uninstaller
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "DisplayName" "DNSSEC/TLSA Validator add-on"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "UninstallString" "$\"$INSTDIR\uninst.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "QuietUninstallString" "$\"$INSTDIR\uninst.exe$\" /S"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "NoModify" "1"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "NoRepair" "1"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "URLInfoAbout" "http://www.dnssec-validator.cz"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "Publisher" "CZ.NIC Labs"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "Version" "${VERSION}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "DisplayVersion" "${VERSION}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "Contact" "CZ.NIC Labs"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "DisplayIcon" "$\"$INSTDIR\key.ico$\""
	${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
	IntFmt $0 "0x%08X" $0
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "EstimatedSize" "$0"
	WriteUninstaller "uninst.exe"


	# start menu items
	!insertmacro MUI_STARTMENU_WRITE_BEGIN DNSSECStartMenu
	CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
	CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk" "$INSTDIR\uninst.exe" "" "" "" "" "" "Uninstall DNSSEC/TLSA Validator add-on for IE"
	CreateShortCut "$SMPROGRAMS\$StartMenuFolder\RegPlugin.lnk" "$INSTDIR\RegPlugin.bat" "" "" "" "" "" "Manual registration of DNSSEC/TLSA Validator add-on"
	CreateShortCut "$SMPROGRAMS\$StartMenuFolder\UnRegPlugin.lnk" "$INSTDIR\UnRegPlugin.bat" "" "" "" "" "" "Manual un-registration of DNSSEC/TLSA Validator add-on"
	!insertmacro MUI_STARTMENU_WRITE_END

	# register DNSSEC toolbar
	RegDLL "$INSTDIR\IEdnssec.dll"
sectionEnd

# setup macros for uninstall functions.
!ifdef UN
!undef UN
!endif
!define UN "un."

# uninstaller section
section "un.Unbound"
	UnRegDLL "$INSTDIR\IEdnssec.dll"
  	# deregister uninstall
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}"
	Delete "$INSTDIR\DNSSECcore-windows-x86.dll" 
	Delete "$INSTDIR\DANEcore-windows-x86.dll"    
	Delete "$INSTDIR\IEdnssec.dll"
	Delete "$INSTDIR\key.ico"
	Delete "$INSTDIR\RegPlugin.bat"
	Delete "$INSTDIR\UnRegPlugin.bat"
	Delete "$LOCALAPPDATA\CZ.NIC\${PROGRAM_NAME}\dnssec.ini"
	RMDir "$LOCALAPPDATA\CZ.NIC\${PROGRAM_NAME}"
	RMDir "$LOCALAPPDATA\CZ.NIC"
	Delete "$INSTDIR\uninst.exe"   # delete self
	RMDir "$PROGRAMFILES\CZ.NIC\${PROGRAM_NAME}"
	RMDir "$PROGRAMFILES\CZ.NIC"
	RMDir "$INSTDIR"

	# start menu items
	!insertmacro MUI_STARTMENU_GETFOLDER DNSSECStartMenu $StartMenuFolder
	Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk"
	Delete "$SMPROGRAMS\$StartMenuFolder\RegPlugin.lnk"
	Delete "$SMPROGRAMS\$StartMenuFolder\UnRegPlugin.lnk"
	RMDir "$SMPROGRAMS\CZ.NIC\${PROGRAM_NAME}"
	RMDir "$SMPROGRAMS\CZ.NIC\"
	RMDir "$SMPROGRAMS\$StartMenuFolder"
	DeleteRegKey HKLM "Software\${PROGRAM_NAME}"
sectionEnd

Function .onInit

	ReadRegStr $R0 HKLM \
	"Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSSECValidator 2.0" \
	"UninstallString"

	ReadRegStr $R1 HKLM \
	"Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" \
	"UninstallString"


	${If} $R0 != "" 
		${If} $LANGUAGE == ${LANG_ENGLISH}
		MessageBox MB_OK|MB_ICONEXCLAMATION \
		"DNSSEC Validator 2.0 is already installed. $\n$\nClick `OK` to remove the \
		installed version." \
		IDOK uninst
		Abort
		${EndIf}

		${If} $LANGUAGE == ${LANG_CZECH}
		MessageBox MB_OK|MB_ICONEXCLAMATION \
		"DNSSEC/TLSA Validator 2.0 byl detekován ve Vašem počítači. $\n$\nStiskněte `OK` pro \
	  	jeho odinstalování." \
		IDOK uninst
		Abort
		${EndIf}

		${If} $LANGUAGE == ${LANG_GERMAN}
		MessageBox MB_OK|MB_ICONEXCLAMATION \
		"DNSSEC Validator 2.0 ist schon installiert. $\n$\nKlicken Sie auf `OK` um die \ installierte Version zu entfernen." \
		IDOK uninst
		Abort
		${EndIf}
	${EndIf}

	${If} $R1 != ""		
		${If} $LANGUAGE == ${LANG_ENGLISH}
		MessageBox MB_OK|MB_ICONEXCLAMATION \
		"DNSSEC/TLSA Validator ${VERSION} is already installed. $\n$\nClick `OK` to remove the \
	  	installed version." \
		IDOK uninst
		Abort
		${EndIf}

		${If} $LANGUAGE == ${LANG_CZECH}
		MessageBox MB_OK|MB_ICONEXCLAMATION \
		"DNSSEC/TLSA Validator ${VERSION} byl detekován ve Vašem počítači. $\n$\nStiskněte `OK` pro \
	  	jeho odinstalování." \
		IDOK uninst
		Abort
		${EndIf}

		${If} $LANGUAGE == ${LANG_GERMAN}
		MessageBox MB_OK|MB_ICONEXCLAMATION \
		"DNSSEC Validator ${VERSION} ist schon installiert. $\n$\nKlicken Sie auf `OK` um die \ installierte Version zu entfernen." \
		IDOK uninst
		Abort
		${EndIf}
	${EndIf}

	;Run the uninstaller
	uninst:
		ClearErrors
		${If} $R0 != "" 
			ExecWait '$R0 _?=$PROGRAMFILES\CZ.NIC\${PROGRAM_NAME_OLD}'
		${EndIf}	
	
		${If} $R1 != "" 
			ExecWait '$R1 _?=$INSTDIR' ;Do not copy the uninstaller to a temp file
		${EndIf}	
	
		IfErrors no_remove_uninstaller done
	
	no_remove_uninstaller:
	
	done:

FunctionEnd
