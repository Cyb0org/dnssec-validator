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
   -> print debug information to standard output (see section DEBUGGING)
 - usetcp [REG_DWORD]
   -> use TCP instead of default UDP for resolving

Please do not change any other extension's option here except those mentioned
above.


DEBUGGING
------------
TODO
