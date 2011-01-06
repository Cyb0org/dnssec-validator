PLUGIN BUILD INSTRUCTIONS
----------------------------

WARNING: This plugin is experimental. Following instuctions currently work
         for Linux plugin version only!

1. Install required packages
  # apt-get install gcc g++ make git cmake

2. Go to the directory, where this file is present.
  $ cd $BUILD_ROOT

3. Get FireBreath from Git
  $ git clone git://github.com/firebreath/FireBreath.git

4. Generate plugin build tree
  $ ./FireBreath/prepmake.sh projects build

  For 32/64bit build define gcc/g++ flag macros:
    -DCMAKE_C_FLAGS=[-m32|-m64] -DCMAKE_CXX_FLAGS=[-m32|-m64]

  For compiler verbose output:
    -DCMAKE_VERBOSE_MAKEFILE=1

5. Build sources
  $ make -C build

6. Enjoy the result plugin
  $ ls build/bin/DNSSECValidator/npDNSSECValidator.so
