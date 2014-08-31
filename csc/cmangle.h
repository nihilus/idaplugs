
/*****************************************************************************
 *                                                                           *
 * cmangle.h: simple regex definitions for parsing not-too comlpex c-mangled *
 * names (pcre-compatible)                                                   *
 * (c) 2006-2007 servil                                                      *
 *                                                                           *
 *****************************************************************************/

#ifndef _cmangle_h_ /* #pragma once */
#define _cmangle_h_


#define WATCHAR "[\\w\\$\\:\\?\\(\\[\\.\\)\\]]"
#define VCCHAR "[\\w\\@\\$\\%\\?]"
#define BCCHAR "[\\w\\@\\$\\%\\&]"
#define VCNAME "[_a-zA-Z]\\w*"
#define BCNAME "[_a-zA-Z]\\w*"
#ifndef FUNC_IMPORT_PREFIX
#define FUNC_IMPORT_PREFIX "__imp_"
#endif // FUNC_IMPORT_PREFIX

// @Graphics@TBitmap@CopyImage$qqruiuirx13tagDIBSECTION (Borland C++ function)
// \1 : @Unit@AllObjects@Func
// \2 : @Object@Func
// \3 : @Object
// \4 : Func
// \5 : @$operator
// \6 : $mangling
#define BCPPPROC "^(?:" FUNC_IMPORT_PREFIX ")?((?:\\@\\w+)*?((\\@" BCNAME ")?\\@{1,2}(" BCNAME ")))(\\@\\$[a-zA-Z]+)?(\\$[a-zA-Z][\\w\\@\\$\\%\\&\\?]+)$"
// @$xp$14System@Boolean (Borland C++ type)
// \1 : Length
// \2 : Var
#define BCPPTYPE "^(?:" FUNC_IMPORT_PREFIX ")?\\@\\$x[pt]\\$(\\d*)([\\w\\@\\$\\%\\&\\?]+)$"
// @Graphics@TBitmap@ (Borland C++ object)
// \0 : @Unit@Object@
// \1 : @Unit
// \2 : @AllObjects
// \3 : @ThisObject
#define BCPPCLASS "^(?:" FUNC_IMPORT_PREFIX ")?(\\@\\w+)?((\\@" BCNAME ")+)\\@$"
// @Forms@Application (Borland C++ variable)
// \1 : Unit
// \2 : @AllObjects@Var
// \3 : @AllObjects
// \4 : @LastObject
// \5 : Var
#define BCPPDATA "^(?:" FUNC_IMPORT_PREFIX ")?\\@(\\w+)(((\\@" BCNAME ")*)\\@([a-zA-Z]\\w*))$"
#define BCPPCONST "^(?:" FUNC_IMPORT_PREFIX ")?\\@(\\w+)(((\\@" BCNAME ")*)\\@_(" VCNAME "))$"
// ?MyFunc@MyClass@@QAEHPAD@Z (Microsoft C++ function)
// \1 : nonstd. prefix (???)
// \2 : Func@Class(es)
// \3 : Func
// \4 : Class(es)
// \5 : type
// \6 : @arglist
#define VCPPPROC "^(?:" FUNC_IMPORT_PREFIX ")?\\?(\\?_*\\d*)?((" VCNAME ")((?:@" VCNAME ")*))@@([QY]\\w+)(@\\w+)?$"
// ?MyClass@@3VMyCppClass@@A (Microsoft C++ variable)
// \1 : ThisVar
// \2 : type
// \3 : @AllOwnerClasses@@mangling
// \4 : @LastOwnerClass
#define VCPPDATA "^(?:" FUNC_IMPORT_PREFIX ")?\\?(" VCNAME ")@@[^QY](\\w+((@" VCNAME ")+@@\\w+)?)$"
// _GetModuleHandleA@4 (Microsoft C any name)
// \1 : Import prefix (optional)
// \2 : Name
// \3 : argsize (optional)
#define VCANYNAME "^(?P<import_prefix>" FUNC_IMPORT_PREFIX ")?(?P<name>" VCNAME ")(?:@(?P<argsize>\\d+))?$"

#endif // _cmangle_h_
