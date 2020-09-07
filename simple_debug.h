
/*
	debug macro

  */
#ifndef __SIMPLE_DEBUG_H__
#define __SIMPLE_DEBUG_H__


extern unsigned int g_simple_debug_flag;

#define SIMPLE_DEBUG_ON(a)           (g_simple_debug_flag |= SIMPLE_DEBUG_FLAG_ ## a)
#define SIMPLE_DEBUG_ON_ALL          (g_simple_debug_flag = 0xffff)
#define SIMPLE_DEBUG_OFF(a)          (g_simple_debug_flag &= ~SIMPLE_DEBUG_FLAG_ ## a)
#define SIMPLE_DEBUG_OFF_ALL         (g_simple_debug_flag = 0)
#define SIMPLE_DEBUG(a)              (g_simple_debug_flag & SIMPLE_DEBUG_FLAG_ ## a)

#define SIMPLE_DEBUG_FLAG_ERROR		(1 << 0)
#define SIMPLE_DEBUG_FLAG_SOCKET     (1 << 1) /* socket */
#define SIMPLE_DEBUG_FLAG_KEEPALIVE	(1 << 2) /*  */
#define SIMPLE_DEBUG_FLAG_RXTX		(1 << 3) /* Rx, Tx */
#define SIMPLE_DEBUG_FLAG_KEY		(1 << 4) /* Key */
#define SIMPLE_DEBUG_FLAG_FUNC1	    (1 << 5) /* function call1 */
#define SIMPLE_DEBUG_FLAG_FUNC2	    (1 << 6) /* function call2 */
#define SIMPLE_DEBUG_FLAG_INFO	    (1 << 7) /* info */
#define SIMPLE_DEBUG_FLAG_PEER		(1 << 8) /* */
#define SIMPLE_DEBUG_FLAG_HS			(1 << 9) /* handshake */
#define SIMPLE_DEBUG_FLAG_ALLON      (0xFFFF)
#define SIMPLE_DEBUG_FLAG_ALLOFF     (0x0000)

#define IS_SIMPLE_DEBUG_ERROR		SIMPLE_DEBUG (ERROR)
#define IS_SIMPLE_DEBUG_SOCKET		SIMPLE_DEBUG (SOCKET)
#define IS_SIMPLE_DEBUG_KEEPALIVE	SIMPLE_DEBUG (KEEPALIVE)
#define IS_SIMPLE_DEBUG_RXTX			SIMPLE_DEBUG (RXTX)
#define IS_SIMPLE_DEBUG_KEY			SIMPLE_DEBUG (KEY)
#define IS_SIMPLE_DEBUG_FUNC1		SIMPLE_DEBUG (FUNC1)
#define IS_SIMPLE_DEBUG_FUNC2		SIMPLE_DEBUG (FUNC2)
#define IS_SIMPLE_DEBUG_INFO		    SIMPLE_DEBUG (INFO)
#define IS_SIMPLE_DEBUG_PEER			SIMPLE_DEBUG (PEER)
#define IS_SIMPLE_DEBUG_HS			SIMPLE_DEBUG (HS)

#define SIMPLE_DEBUG_ERROR(...)   \
	    do {\
	        if (IS_SIMPLE_DEBUG_ERROR)   \
			        fprintf (stderr, __VA_ARGS__); \
			    }while(0)
                
#define SIMPLE_DEBUG_SOCKET(...)  \
	    do {\
	        if (IS_SIMPLE_DEBUG_SOCKET)   \
					fprintf (stderr, __VA_ARGS__);\
			    }while(0)

#define SIMPLE_DEBUG_KEEPALIVE(...)  \
	    do {\
	        if (IS_SIMPLE_DEBUG_KEEPALIVE)   \
			        fprintf (stderr, __VA_ARGS__); \
			    }while(0)

#define SIMPLE_DEBUG_RXTX(...)  \
	    do {\
	        if (IS_SIMPLE_DEBUG_RXTX)   \
			        fprintf (stderr, __VA_ARGS__);  \
			    }while(0)

#define SIMPLE_DEBUG_KEY(...)  \
	    do {\
	        if (IS_SIMPLE_DEBUG_KEY)   \
			        fprintf (stderr, __VA_ARGS__);  \
			    }while(0)

#define SIMPLE_DEBUG_FUNC1(...)  \
	    do {\
	        if (IS_SIMPLE_DEBUG_FUNC1)   \
			        fprintf (stderr, __VA_ARGS__);  \
			    }while(0)

#define SIMPLE_DEBUG_FUNC2(...)  \
	    do {\
	        if (IS_SIMPLE_DEBUG_FUNC2)   \
			        fprintf (stderr, __VA_ARGS__);  \
			    }while(0)

#define SIMPLE_DEBUG_INFO(...)  \
	    do {\
	        if (IS_SIMPLE_DEBUG_INFO)   \
			        fprintf (stderr, __VA_ARGS__);  \
			    }while(0)

#define SIMPLE_DEBUG_PEER(...)  \
	    do {\
	        if (IS_SIMPLE_DEBUG_PEER)   \
			        fprintf (stderr, __VA_ARGS__);  \
			    }while(0)

#define SIMPLE_DEBUG_HS(...)  \
	    do {\
	        if (IS_SIMPLE_DEBUG_HS)   \
			        fprintf (stderr, __VA_ARGS__);  \
			    }while(0)


#endif /*__SIMPLE_DEBUG_H__*/
