This file describes DNSSEC Firefox extension build dependencies
and build instructions.


### LIBRARIES ###

libldns (http://www.nlnetlabs.nl/projects/ldns/)
openssl (http://www.openssl.org)

No need to get these libraries, already built in GIT.

openssl:
* ./Configure linux-x86_64 shared -fPIC                      [Lin]
* ./Configure linux-generic32 shared -fPIC -m32              [Lin]
* ./Configure darwin-i386-cc shared                          [Mac]
* ./Configure darwin-ppc-cc shared                           [Mac]
make
make test
ln -s . lib                            (needed for successful build of libldns)
* http://www.slproweb.com/download/Win32OpenSSL-0_9_8l.exe   [Win]
* mv libeay32.dll crypto.dll                                 [Win]
* (strip -x -S ...)                                          [Lin]

libldns:
* export CFLAGS="-m64 -fPIC"                                 [Lin]
* export CFLAGS="-m32 -fPIC"                                 [Lin]
* export CFLAGS="-arch i386"                                 [Mac]
* export CFLAGS="-arch ppc"                                  [Mac]
* export CC="$HOME/tools/mingw-w32/bin/i686-w64-mingw32-gcc" [Win]
* ./configure --with-ssl=../openssl-0.9.8l --host=mingw32    [Win]
* [Makefile: s/-l.../-Wl,-l.../]                             [Win]
* ./configure --with-ssl=../openssl-0.9.8l                   [Lin, Mac]
make
* (strip -x -S ...)                                          [Lin]
* (i686-w64-mingw32-strip -x -S ...)                         [Win]


### LINUX (expected Debian GNU/Linux unstable amd64) ###

xulrunner SDK:
xulrunner-dev package
ftp://ftp.mozilla.org/pub/mozilla.org/xulrunner/releases/1.9.1.4/sdk/xulrunner-1.9.1.4.en-US.linux-i686.sdk.tar.bz2


### MAC OS X ###

Xcode for Mac-only Development (gcc, make, ...):
http://developer.apple.com/technology/xcode.html

xulrunner SDK:
ftp://ftp.mozilla.org/pub/mozilla.org/xulrunner/releases/1.9.1.4/sdk/xulrunner-1.9.1.4.en-US.mac-i386.sdk.tar.bz2
ftp://ftp.mozilla.org/pub/mozilla.org/xulrunner/releases/1.9.1.4/sdk/xulrunner-1.9.1.4.en-US.mac-powerpc.sdk.tar.bz2

(www.macports.org)
(libidl)
(xpidl: libintl.3.dylib -> libintl.dylib)


### Windows ###

xulrunner SDK:
ftp://ftp.mozilla.org/pub/mozilla.org/xulrunner/releases/1.9.1.4/sdk/xulrunner-1.9.1.4.en-US.win32.sdk.zip

mingw-w64:
http://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Release%20for%20GCC%204.4.1/mingw-w32-bin_x86-64-linux_4.4.1a.tar.bz2/download
(http://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Release%20for%20GCC%204.4.1/mingw-w64-bin_x86-64-linux_4.4.1-1a.tar.bz2/download)
