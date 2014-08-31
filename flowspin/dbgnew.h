
#if defined(_MSC_VER) && defined(__cplusplus) \
	&& defined(_DEBUG) && !defined(new) && !defined(_NO_DEBUG_NEW)
#define new ::new(_NORMAL_BLOCK, __FILE__, __LINE__)
#endif
