
// NuMega BoundsChecker API

#ifndef _NmApiLib_h_
#define _NmApiLib_h_ 1

#ifdef NMBC

#include <NmApiLib.h>

#else // !NMBC

#define StartEvtReporting           __noop
#define StopEvtReporting            __noop
#define EvtReportingState           __noop
#define NMEnableErrorPopup          __noop
#define NMMemMark                   __noop
#define NMMemSave                   __noop
#define NMMemPopup                  __noop
#define NMMemTrackCheckHeapBlocks   __noop

#endif // NMBC

#endif // !_NmApiLib_h_
