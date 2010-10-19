This file describes DNSSEC Firefox extension build dependencies
and build instructions.


### LIBRARIES ###

libldns (https://www.nlnetlabs.nl/projects/ldns/)
openssl (https://www.openssl.org)

No need to get these libraries, they are already built in GIT.

openssl 1.0.0a:
* ./Configure linux-x86_64 enable-static-engine -D_GNU_SOURCE -fPIC                        [Lin]
* ./Configure linux-generic32 enable-static-engine -D_GNU_SOURCE -fPIC -m32                [Lin]
* (./Configure darwin-i386-cc shared -mmacosx-version-min=10.4)                            [Mac]
* ./Configure darwin-i386-cc enable-static-engine -mmacosx-version-min=10.4 -fPIC          [Mac]
* (./Configure darwin-ppc-cc shared -mmacosx-version-min=10.4)                             [Mac]
* ./Configure darwin-ppc-cc enable-static-engine -mmacosx-version-min=10.4                 [Mac]
* ./Configure --cross-compile-prefix=i586-mingw32msvc- mingw enable-static-engine          [Win]
make
make test
ln -s . lib                            (needed for successful build of libldns)
* (strip -x -S ...)                                                                        [Lin]
* (i586-mingw32msvc-strip -x -S ...)                                                       [Win]

libldns r3366:
* export CFLAGS="-m64 -fPIC"                                                               [Lin]
* export CFLAGS="-m32 -fPIC"                                                               [Lin]
* export CFLAGS="-arch i386 -mmacosx-version-min=10.4 -fPIC"                               [Mac]
* export CFLAGS="-arch ppc -mmacosx-version-min=10.4"                                      [Mac]
* export CC="i586-mingw32msvc-gcc"                                                         [Win]
* ./configure --disable-shared --with-ssl=../openssl-1.0.0a --host=mingw32                 [Win]
* [Makefile: s/-l.../-Wl,-l.../]                                                           [Win]
* ./configure --disable-shared --with-ssl=../openssl-1.0.0a                           [Lin, Mac]
make
* i586-mingw32msvc-ranlib .libs/libldns.a                                                  [Win]
* (strip -x -S ...)                                                                        [Lin]
* (i586-mingw32msvc-strip -x -S ...)                                                       [Win]


### LINUX (expected Debian GNU/Linux unstable amd64) ###

GCC:
gcc-4.4 package (v4.2 should be enough)
g++-4.4 package (v4.2 should be enough)
(lib32gcc1)
(lib32stdc++6)

xulrunner SDK:
xulrunner-dev package
ftp://ftp.mozilla.org/pub/mozilla.org/xulrunner/releases/1.9.1.7/sdk/xulrunner-1.9.1.7.en-US.linux-i686.sdk.tar.bz2

(ia32-libs)


### MAC OS X ###

Xcode 3.1 for Mac-only Development (gcc, make, ...):
http://developer.apple.com/technology/xcode.html

xulrunner SDK:
ftp://ftp.mozilla.org/pub/mozilla.org/xulrunner/releases/1.9.1.7/sdk/xulrunner-1.9.1.7.en-US.mac-i386.sdk.tar.bz2
ftp://ftp.mozilla.org/pub/mozilla.org/xulrunner/releases/1.9.1.7/sdk/xulrunner-1.9.1.7.en-US.mac-powerpc.sdk.tar.bz2

(www.macports.org)
(libidl)
(xpidl: libintl.3.dylib -> libintl.dylib)


### Windows ###

Microsoft Visual C++ 2008 Express Edition:
http://www.microsoft.com/express/Downloads/

xulrunner SDK:
ftp://ftp.mozilla.org/pub/mozilla.org/xulrunner/releases/1.9.1.7/sdk/xulrunner-1.9.1.7.en-US.win32.sdk.zip

MingW32/MingW64:
gcc-mingw32 package
