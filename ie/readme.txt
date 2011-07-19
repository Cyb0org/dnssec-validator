DNSSEC Validator extension for Microsoft Internet Explorer
<http://www.dnssec-validator.cz>
----------------------------------------------------------

INSTALLATION
---------------
TODO


CONFIGURATION
----------------
Extension could be configured through the Windows system registry.

Key: HKEY_CURRENT_USER\Software\CZ.NIC\DNSSEC Validator

Parameters:
 - dnsserveraddr [REG_SZ]
   -> list containing DNS resolver's IPv4/IPv6 address(es)
      (system DNS configuration is used when list is empty or does not exist)
 - debugoutput [REG_DWORD]
   -> print resolving library debug information to standard output
 - usetcp [REG_DWORD]
   -> use TCP instead of default UDP for resolving

Please do not change any other extension's option here except those mentioned
above.


DEBUGGING
------------
For enabling debug info of an extension:
 - select "Debug" configuration (Build -> Configuration Manager...)
 - run IE in single process mode (set HKEY_CURRENT_USER\Software\Microsoft\
   Internet Explorer\Main\TabProcGrowth = 0 [REG_DWORD])


TODO
-------
Differences against Firefox version:
 - no cache
 - no asynchronous mode
 - no browser (system) IP comparison
 - no icon refreshing when switching back to an opened tab
 - no popup window with information text
 - no preferences window
