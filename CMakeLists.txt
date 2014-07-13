# Simple script that will setup some variables to be used for recursive build
# of dependent libraries like openssl, ldns and unbound.

# On Mac, 2.8 is required due to the use of CMAKE_OSX_ARCHITECTURES
# Requirement for 2.8 is specified on Mac branch below.
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
 
PROJECT(C++)

## Variables set by this script:
# OPENSSL_ARGS - args passed to openssl's ./Configure
# CONFIGURE_ARGS - args passed to autotools' ./configure (for ldns and unbound)
# LIB_CFLAGS - CFLAGS for dependent libraries
# OS_TARGET - target OS name build is made for
# STATIC_LINKING - whether to statically link openssl, ldns and unbound
# INCLUDE_LOC - where to search for header files
# LIBRARY_LOC - where to search for libraries
 
SET(LIB_CFLAGS "${LIB_CFLAGS} -fPIC")
SET(BUILD_MAC96 0)
SET(MAKE_CMD "make")

# If build arch is not explicitly set, use current
IF(NOT DEFINED TARGET_ARCH)
    SET(TARGET_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
    SET(BUILD_MAC96 1)
    SET(LIB_CFLAGS_MAC ${LIB_CFLAGS})
ENDIF()

# Set flags for dependent libraries, if/else hell on wheels
IF(TARGET_ARCH STREQUAL "amd64")
    SET(LIB_CFLAGS "${LIB_CFLAGS} -m64")
    SET(BUILD_64BIT 1)
ELSEIF(TARGET_ARCH STREQUAL "x86_64")
    SET(LIB_CFLAGS "${LIB_CFLAGS} -m64")
    SET(BUILD_64BIT 1)
ELSEIF(TARGET_ARCH MATCHES "^(i.86|x86)$")
    SET(LIB_CFLAGS "${LIB_CFLAGS} -m32")
    SET(BUILD_64BIT 0)
ELSE()
    MESSAGE(SEND_ERROR "Unsupported architecture - '${TARGET_ARCH}'")
ENDIF()

# Check whether to disable static linking. Default is on.
IF(STATIC_LINKING STREQUAL "no")
    MESSAGE("Linking dynamically")
ELSE()
    SET(STATIC_LINKING "yes")
    MESSAGE("Linking statically")
ENDIF()

IF(WIN32)
    SET(OS_TARGET "WINDOWS")
    SET(OPENSSL_ARGS "mingw ${LIB_CFLAGS}")
    SET(CONFIGURE_ARGS "--cross-compile-prefix=i586-mingw32msvc-")
    MESSAGE("WIN")
ELSEIF(UNIX)
    IF(APPLE)
        CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
        SET(OS_TARGET "MAC")
	SET(OSNAME "MacOSX")
	SET(OSNAME_LC "macosx")
	IF(BUILD_MAC96)
	    SET(LIB_CFLAGS "${LIB_CFLAGS_MAC} -arch i386 -arch x86_64")
	    SET(OPENSSL_ARGS "darwin64-x86_64-cc ${LIB_CFLAGS}")
	    SET(CMAKE_OSX_ARCHITECTURES "i386;x86_64")
	    MESSAGE("APPLE i386;x86_64")
	ELSEIF(BUILD_64BIT)
            SET(OPENSSL_ARGS "darwin64-x86_64-cc ${LIB_CFLAGS}")
            SET(CONFIGURE_ARGS "--target=x86_64-apple-darwin11")
            SET(CMAKE_OSX_ARCHITECTURES "x86_64")
	    MESSAGE("APPLE x86_64")
        ELSE()
            SET(OPENSSL_ARGS "darwin-i386-cc ${LIB_CFLAGS}")
            SET(CONFIGURE_ARGS "--target=i686-apple-darwin11")
            SET(CMAKE_OSX_ARCHITECTURES "i386")
	    MESSAGE("APPLE i386")
        ENDIF()
    ELSE() # Linux
        SET(OS_TARGET "UNIX")
	IF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
            SET(MAKE_CMD "gmake")
            SET(OSNAME "FreeBSD")
            SET(OSNAME_LC "freebsd")
            IF(BUILD_64BIT)
	        SET(OPENSSL_ARGS "BSD-x86_64 ${LIB_CFLAGS}")
	        SET(CONFIGURE_ARGS "--target=x86_64-pc-freebsd")
	        MESSAGE("FREEBSD x86_64")
            ELSE()
            ENDIF()
        ELSEIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
            SET(MAKE_CMD "make")
            SET(OSNAME "Linux")
            SET(OSNAME_LC "linux")
            IF(BUILD_64BIT)
                SET(OPENSSL_ARGS "linux-x86_64 ${LIB_CFLAGS}")
                SET(CONFIGURE_ARGS "--target=x86_64-pc-linux-gnu")
	        MESSAGE("LINUX x86_64")
            ELSE()
                SET(OPENSSL_ARGS "linux-elf ${LIB_CFLAGS}")
                SET(CONFIGURE_ARGS "--target=i686-pc-linux-gnu")
	        MESSAGE("LINUX x86")
            ENDIF()
        ELSE()
            MESSAGE(SEND_ERROR "Unsupported *NIX derivative '${${CMAKE_SYSTEM_NAME}}'.")
        ENDIF()
    ENDIF()
ELSE()
    MESSAGE(SEND_ERROR "Unsupported OS")
ENDIF()

# Recursive build using Makefile.main is the target
ADD_CUSTOM_TARGET(RecursiveBuild ALL)

# Calling Makefile.main passing the set variables on command line
ADD_CUSTOM_COMMAND(TARGET RecursiveBuild 
    COMMAND ${MAKE_CMD} 
    ARGS -f Makefile.main 
        LIB_CFLAGS=${LIB_CFLAGS}
        OPENSSL_ARGS=${OPENSSL_ARGS} 
        CONFIGURE_ARGS=${CONFIGURE_ARGS} 
        OS_TARGET=${OS_TARGET}
        CMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
        XPI_ARCH=${TARGET_ARCH}
        BUILD_64BIT=${BUILD_64BIT}
        BUILD_MAC96=${BUILD_MAC96}
        OSNAME=${OSNAME}
        OSNAME_LC=${OSNAME_LC}
	MAKE_CMD=${MAKE_CMD}
	STATIC_LINKING=${STATIC_LINKING}
	INCLUDE_LOC=${INCLUDE_LOC}
	LIBRARY_LOC=${LIBRARY_LOC}
    )
