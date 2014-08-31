
Before all my plugins are purely experimantal works and I guarantee nothing.
The source code was tuned for MSVC 7.1. Port to other compiler is possible but
may require quite alots of code adjustments (I didnot care for portability nor
test another compiler). To compile the plugin for IDA, you need:

1. ofcourse all the sourcefiles from this package extracted
2. ofcourse IDA SDK for version being executed on
3. Microsoft Visual C++ 7.x or above, or Intel compiler installed (ofcourse)
4. for most plugins PCRE library compiled
   (ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/)
5. STL implementation (C++ stdlib may be enough but I did not enforce std. STL
   compatibility, in case of standard deviation go with STLport at http://stlport.sourceforge.net/)
6. Boost library (http://boost.org/) - just the headers
7. Windows Platform SDK (subset from Visual Studio should be sufficient - if not,
   go with PSDK at http://www.microsoft.com/msdownload/platformsdk/sdkupdate/)
8. some other tools (see comments)


Build instructions:

1-stly, the package should be complete (ie. no files except 3-rd party SDK's
enlisted above should be missing to build the plugin), however I collected the
sourcefiles from various locations of my home PC and didnot test the compile
elsewhere, this means some files may be missing, in such case let me know.
2-ndly, I'm hard to maintain easy-to-setup distribution. This means you will
surely need to adjust makefiles to build successfully. At least some hard paths
in basicdef.mak will require adjustments to reflect local machine configuration.
Probably some other things will need reconfigure (eg. use*.mak files for
library names).

To make build from command line: run known vcvars32.bat of VS distribution, then

do {
  nmake -f<plugin>.mak
  if (errors > 0) <fix errors>
} while (errors > 0);


Comments:
Remove all occurences of binsr tool from common.mak, this is not required. The
image is packed with upx by default: because upx doesnot restore attributes of
sections, to ensure exception handling will work correctly final image must be
post-processed by chkrdata tool (source is incluided in this package). The tool
will be used automatically by makefiles. If you are lazy or fail for other
reason build chkrdata tool, leave the plugin unpacked (remove upx from
common.mak and comment-out the VirtualProtect call in DllMain of main
sourcefile).

For missing files or other unresolvable portability problems mail me to
<servil@gmx.net>.
