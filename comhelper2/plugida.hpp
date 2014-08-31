
/*****************************************************************************
 *                                                                           *
 * plugida.hpp: common inclusions and defines for ida plugins                *
 * (c) 2003-2008 servil                                                      *
 *                                                                           *
 *****************************************************************************/

#ifndef _PLUGIDA_HPP_
#define _PLUGIDA_HPP_

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#	pragma warning(disable:   47) // incompatible redefinition of macro "XXX"
#	pragma warning(disable:  181) // argument is incompatible with corresponding format string conversion
#	pragma warning(disable:  186) // pointless comparison of unsigned integer with zero
#	pragma warning(disable:  269) // invalid format string conversion
#	pragma warning(disable:  411) // class "xxxx" defines no constructor to initialize...
#	pragma warning(disable: 1011) // missing return statement at end of non-void function
#elif defined(_MSC_VER)
#	pragma warning(disable: 4005) // 'identifier' : macro redefinition
#	pragma warning(disable: 4183) // 'identifier': missing return type; assumed to be a member function returning 'int'
#	pragma warning(disable: 4288) // nonstandard extension used : 'var' : loop control variable declared in the for-loop is used outside the for-loop scope; it conflicts with the declaration in the outer scope
#	pragma warning(disable: 4503) // 'identifier' : decorated name length exceeded, name was truncated
#endif

#define NOMINMAX                    1 // don't mess-up PSDK's macro with std::min/max<>

#define BYTES_SOURCE                1
/*
#define ENUM_SOURCE                 1
#define USE_DANGEROUS_FUNCTIONS     1
#define USE_STANDARD_FILE_FUNCTIONS 1
*/

#include "undbgnew.h"

// system
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <malloc.h>
#include <excpt.h>
#include "mscrtdbg.h"
#include "msvc70rt.h"
#include <memory>
#include <string>
#include <stdexcept>
#include <typeinfo>
#include <new>
#include <windows.h>
#include "NmApiLib.hpp"

// ida library
#include "plg_rsrc.h"
#include "idasdk.hpp"
#include "idaview.hpp"
#include "areaex.hpp"
#include "plughlpr.hpp"
#include "plugxcpt.hpp"
#include "plugsys.hpp"
#include "plugcmn.hpp"
#include "plugtinf.hpp"
#include "plugcom.hpp"
#include "plugstrm.hpp"
#include "pluginsn.hpp"
#include "plugfgrp.hpp"
#include "plugbizy.hpp"

#include "dbgnew.h"

// ensure old 'good' VC6 for-scope compatibility
#if defined(_MSC_VER) && !defined(_NO_NOFORSCOPE)
#pragma conform(forScope, off)
#endif

// this is for convenience
#ifndef _NO_USING_STD
using namespace std;
#endif

#endif // _PLUGIDA_HPP_
