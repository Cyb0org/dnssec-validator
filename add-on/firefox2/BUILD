This file describes DNSSEC Firefox add-on build dependencies
and build instructions.


### GENERAL REQUIREMENTS ###
  - OS: GNU/Linux | Mac OS X | MS Windows
  - CMake >=2.8 <http://www.cmake.org>
  - FireBreath <http://www.firebreath.org>


### LINUX (expected Debian GNU/Linux unstable amd64) ###
  # apt-get install gcc g++ lib32gcc1 lib32stdc++6 libc6-dev-i386 make git cmake zip sed pkg-config libgtk2.0-dev
  $ git clone git://github.com/firebreath/FireBreath.git plugin/FireBreath
  $ (cd plugin/FireBreath; git checkout f21613137c4c0cfb24679197ea706b31effdd956)
  $ make sys_linux
  $ ls dnssec_validator-<version>-linux.xpi


### MAC OS X ###
  - install Xcode 3.1 for Mac-only Development (gcc, make, ...)
    <http://developer.apple.com/technology/xcode.html>
  - install MacPorts <http://www.macports.org/install.php>
  $ sudo port install git-core cmake
  $ git clone git://github.com/firebreath/FireBreath.git plugin/FireBreath
  $ (cd plugin/FireBreath; git checkout f21613137c4c0cfb24679197ea706b31effdd956)
  $ make sys_macosx
  $ ls dnssec_validator-<version>-macosx.xpi


### WINDOWS ###
  Part 1 - to be built on Linux:
  # apt-get install gcc-mingw32 make git sed zip
  $ git clone git://github.com/firebreath/FireBreath.git plugin/FireBreath
  $ (cd plugin/FireBreath; git checkout f21613137c4c0cfb24679197ea706b31effdd956)
  $ make sys_windows_pre

  Part 2 - to be built on Windows:
  - install CMake <http://www.cmake.org/cmake/resources/software.html>  
  Visual Studio Professional variant:
    - install Microsoft Visual Studio 2010 Professional Edition
      <http://www.microsoft.com/visualstudio/en-us/home>
    > plugin\FireBreath\prep2010.cmd plugin\projects plugin\build
  Visual Studio Express variant:
    - install Windows Driver Kit (7.1.0 or later)
      <http://www.microsoft.com/whdc/DevTools/WDK/WDKpkg.mspx>
    - install Microsoft Visual C++ 2008 Express Edition
      <http://www.microsoft.com/express/Downloads/>
    > plugin\FireBreath\prep2008.cmd plugin\projects plugin\build
  - run VC++, open plugin/build/FireBreath.sln, select "MinSizeRel"
    configuration (Build -> Configuration Manager...) and build it

  Part 3 - to be built on Linux:
  $ make sys_windows_post
  $ ls dnssec_validator-<version>-windows.xpi


### LIBRARIES ###

Note: No need to get/build these libraries. They are already built in the Git
repository in the ./plugin/lib directory.

libldns (https://www.nlnetlabs.nl/projects/ldns/)
openssl (https://www.openssl.org)

openssl 1.0.0a:
* ./Configure linux-x86_64 enable-static-engine -D_GNU_SOURCE -fPIC -Wa,--noexecstack               [Lin]
* ./Configure linux-generic32 enable-static-engine -D_GNU_SOURCE -fPIC -m32 -Wa,--noexecstack       [Lin]
* (./Configure darwin-i386-cc shared -mmacosx-version-min=10.4)                                     [Mac]
* ./Configure darwin-i386-cc enable-static-engine -mmacosx-version-min=10.4 -fPIC                   [Mac]
* (./Configure darwin64-x86_64-cc shared -mmacosx-version-min=10.4)                                 [Mac]
* ./Configure darwin64-x86_64-cc enable-static-engine -mmacosx-version-min=10.4                     [Mac]
* ./Configure --cross-compile-prefix=i586-mingw32msvc- mingw enable-static-engine                   [Win]
make
make test
ln -s . lib                            (needed for successful build of libldns)
* mv libcrypto.a libcrypto.a.i386                                                                   [Mac]
* mv libcrypto.a libcrypto.a.x86_64                                                                 [Mac]
* lipo -create -output libcrypto.a libcrypto.a.i386 libcrypto.a.x86_64                              [Mac]
* (strip -x -S ...)                                                                                 [Lin]
* (i586-mingw32msvc-strip -x -S ...)                                                                [Win]

libldns r3366:
* export CFLAGS="-m64 -fPIC"                                                                        [Lin]
* export CFLAGS="-m32 -fPIC"                                                                        [Lin]
* export CFLAGS="-arch i386 -mmacosx-version-min=10.4 -fPIC"                                        [Mac]
* export CFLAGS="-arch x86_64 -mmacosx-version-min=10.4"                                            [Mac]
* export CC="i586-mingw32msvc-gcc"                                                                  [Win]
* ./configure --disable-shared --with-ssl=../openssl-1.0.0a --host=mingw32                          [Win]
* [Makefile: s/-l.../-Wl,-l.../]                                                                    [Win]
* ./configure --disable-shared --with-ssl=../openssl-1.0.0a                                    [Lin, Mac]
make
* i586-mingw32msvc-ranlib .libs/libldns.a                                                           [Win]
* mv lib/libldns.a libldns.a.i386                                                                   [Mac]
* mv lib/libldns.a libldns.a.x86_64                                                                 [Mac]
* lipo -create -output libldns.a libldns.a.i386 libldns.a.x86_64                                    [Mac]
* (strip -x -S ...)                                                                                 [Lin]
* (i586-mingw32msvc-strip -x -S ...)                                                                [Win]
