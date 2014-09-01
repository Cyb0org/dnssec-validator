# The NSIS (http://nsis.sourceforge.net) install script.
# This script is BSD licensed.
SetCompressor /solid /final lzma

!include LogicLib.nsh
!include MUI2.nsh
!include FileFunc.nsh
!include ReplaceInFile.nsh
!include StrRep.nsh

!define VERSION "2.2.0"
!define QUADVERSION "2.2.0.0"
!define guid '{669695BC-A811-4A9D-8CDF-BA8C795F261B}'
!define PROGRAM_NAME "Chrome TLSA Validator"
outFile ".\..\..\packages\tlsa-plugin-${VERSION}.x-windows-x86.exe"
Name "Chrome TLSA Validator ${VERSION}"

# default install directory
installDir "$PROGRAMFILES\CZ.NIC\${PROGRAM_NAME}"
installDirRegKey HKLM "Software\${PROGRAM_NAME}" "InstallLocation"
RequestExecutionLevel admin
#give credits to Nullsoft: BrandingText ""
VIAddVersionKey "ProductName" "${PROGRAM_NAME} ${VERSION}"
VIAddVersionKey "CompanyName" "CZ.NIC Labs"
VIAddVersionKey "FileDescription" "(un)install the ${PROGRAM_NAME} ${VERSION} for Google Chrome"
VIAddVersionKey "LegalCopyright" "Copyright 2014, CZ.NIC Labs"
VIAddVersionKey "FileVersion" "${QUADVERSION}"
VIAddVersionKey "ProductVersion" "${QUADVERSION}"
VIProductVersion "${QUADVERSION}"

# Global Variables
Var StartMenuFolder

# use ReserveFile for files required before actual installation
# makes the installer start faster
#ReserveFile "System.dll"
#ReserveFile "NsExec.dll"

!define MUI_ICON "tlsakey.ico"
!define MUI_UNICON "tlsakey.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP ".\..\common\setup_top.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP ".\..\common\setup_left.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP ".\..\common\setup_left.bmp"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_TITLE_3LINES
;!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of ${PROGRAM_NAME} ${VERSION} add-on.$\r$\n$\nNote: It is recommended to close all running Google Chrome windows before proceeding with the installation of the add-on.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "../../COPYING"
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

  Var /GLOBAL INSTDIRCOPY
  StrCpy $INSTDIRCOPY $INSTDIR

	File ".\..\..\plugins-lib\DANEcore-windows-x86.exe"
	File ".\..\..\add-on\chrome-tlsa\native-msg\cz.nic.validator.tlsa.json.in"
  Rename cz.nic.validator.tlsa.json.in cz.nic.validator.tlsa.json
  
  Push "$INSTDIRCOPY" ;original string
  Push "\" ;needs to be replaced
  Push "\\" ;will replace wrong characters
  Call StrRep
  Pop $0
    
  !insertmacro _ReplaceInFile "cz.nic.validator.tlsa.json" "@DANE_BINARY@" "$\"$0\\DANEcore-windows-x86.exe$\""
  Delete "$INSTDIR\cz.nic.validator.tlsa.json.old"
  
  
	# store installation folder
	WriteRegStr HKLM "Software\${PROGRAM_NAME}" "InstallLocation" "$INSTDIR"
	# register uninstaller
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "DisplayName" "${PROGRAM_NAME} add-on"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "UninstallString" "$\"$INSTDIR\uninst.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "QuietUninstallString" "$\"$INSTDIR\uninst.exe$\" /S"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "NoModify" "1"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "NoRepair" "1"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "URLInfoAbout" "https://www.dnssec-validator.cz"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "Publisher" "CZ.NIC Labs"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "Version" "${VERSION}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "DisplayVersion" "${VERSION}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "Contact" "CZ.NIC Labs"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "DisplayIcon" "$\"$INSTDIR\tlsakey.ico$\""
  WriteRegStr HKCU "Software\Google\Chrome\NativeMessagingHosts\cz.nic.validator.tlsa" "" "$INSTDIR\cz.nic.validator.tlsa.json"
  WriteRegStr HKCU "Software\Chromium\NativeMessagingHosts\cz.nic.validator.tlsa" "" "$INSTDIR\cz.nic.validator.tlsa.json"
       
	${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
	IntFmt $0 "0x%08X" $0
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" "EstimatedSize" "$0"
	WriteUninstaller "uninst.exe"
  
	# start menu items
	!insertmacro MUI_STARTMENU_WRITE_BEGIN DNSSECStartMenu
	CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
	CreateShortCut "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk" "$INSTDIR\uninst.exe" "" "" "" "" "" "Uninstall ${PROGRAM_NAME} add-on for Chrome"
	!insertmacro MUI_STARTMENU_WRITE_END
sectionEnd

# setup macros for uninstall functions.
!ifdef UN
!undef UN
!endif
!define UN "un."

# uninstaller section
section "un.Unbound"
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}"
  DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\cz.nic.validator.tlsa"
  DeleteRegKey HKCU "Software\Chromium\NativeMessagingHosts\cz.nic.validator.tlsa"
	Delete "$INSTDIR\DANEcore-windows-x86.exe"
  Delete "$INSTDIR\cz.nic.validator.tlsa.json"
  Delete "$INSTDIR\uninst.exe"    
	RMDir "$PROGRAMFILES\CZ.NIC\${PROGRAM_NAME}"
	RMDir "$PROGRAMFILES\CZ.NIC"
	RMDir "$INSTDIR"

	# start menu items
	!insertmacro MUI_STARTMENU_GETFOLDER DNSSECStartMenu $StartMenuFolder
	Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk"
	RMDir "$SMPROGRAMS\CZ.NIC\${PROGRAM_NAME}"
	RMDir "$SMPROGRAMS\CZ.NIC\"
	RMDir "$SMPROGRAMS\$StartMenuFolder"
	DeleteRegKey HKLM "Software\${PROGRAM_NAME}"
sectionEnd

Function .onInit

	ReadRegStr $R0 HKLM \
	"Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" \
	"UninstallString"

	${If} $R0 != ""		
		${If} $LANGUAGE == ${LANG_ENGLISH}
		MessageBox MB_OK|MB_ICONEXCLAMATION \
		"${PROGRAM_NAME} ${VERSION} is already installed. $\n$\nClick `OK` to remove the \
	  	installed version." \
		IDOK uninst
		Abort
		${EndIf}

		${If} $LANGUAGE == ${LANG_CZECH}
		MessageBox MB_OK|MB_ICONEXCLAMATION \
		"${PROGRAM_NAME} ${VERSION} byl detekován ve Vašem počítači. $\n$\nStiskněte `OK` pro \
	  	jeho odinstalování." \
		IDOK uninst
		Abort
		${EndIf}

		${If} $LANGUAGE == ${LANG_GERMAN}
		MessageBox MB_OK|MB_ICONEXCLAMATION \
		"${PROGRAM_NAME} ${VERSION} ist schon installiert. $\n$\nKlicken Sie auf `OK` um die \ installierte Version zu entfernen." \
		IDOK uninst
		Abort
		${EndIf}
	${EndIf}

	;Run the uninstaller
	uninst:
		ClearErrors	
		${If} $R0 != "" 
			ExecWait '$R0 _?=$INSTDIR' ;Do not copy the uninstaller to a temp file
		${EndIf}	
	
		IfErrors no_remove_uninstaller done
	
	no_remove_uninstaller:
	
	done:

FunctionEnd