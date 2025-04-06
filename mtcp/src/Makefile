.PHONY: clean

### TARGET ###
PS=0
DPDK=1
ENFORCE_RX_IDLE=0
NETMAP=0
ONVM=0
LRO=0
CCP=
HWCSUM=1
MTCP_LIB_DIR=../../install/lib
MTCP_LIB=libmtcp.a
MTCP_HDR_DIR=../../install/include
MTCP_HDR = mtcp_api.h mtcp_epoll.h

### GCC ###
GCC=gcc

### FLAGS ###
ifeq ($(shell uname -m),x86_64)
GCC_OPT = -m64
else
GCC_OPT =
endif


GCC_OPT += -Wall -fPIC -fgnu89-inline -Werror -Wno-error=unused-variable


GCC_OPT += -DNDEBUG -O3 -DINFO -DDBGERR -DDBGCERR
GCC_OPT += $(DBG_OPT)
GCC_OPT += -D__USRLIB__

ifeq ($(LRO),1)
GCC_OPT += -DENABLELRO
endif

ifeq ($(CCP),1)
GCC_OPT += -DUSE_CCP
endif

ifeq ($(HWCSUM),0)
GCC_OPT += -DDISABLE_HWCSUM
endif

### LIBRARIES AND INCLUDES ###
INC_DIR=./include
INC= -I$(INC_DIR)


INC += -DDISABLE_PSIO


ifeq ($(NETMAP),1)
# do nothing
else
INC += -DDISABLE_NETMAP
endif

# PacketShader LIBRARY and HEADER
PS_DIR=../../io_engine
INC += -I$(PS_DIR)/include

# CFLAGS for DPDK-related compilation
ifeq ($(DPDK), 1)
CFLAGS+=$(shell pkg-config --cflags libdpdk)
LDFLAGS+=$(shell pkg-config --libs libdpdk)
# include $(RTE_SDK)/mk/rte.vars.mk
CFLAGS+=-DMAX_CPUS=8 -Wno-stringop-truncation

ifeq ($(ENFORCE_RX_IDLE), 1)
INC += -DENFORCE_RX_IDLE -DRX_IDLE_THRESH=0
endif
else
INC += -DDISABLE_DPDK
endif

$(info "########################################################################")
$(info CFLAGS=$(CFLAGS))
$(info DPDK=$(DPDK))
TEEEE:=$(shell pkg-config --cflags libdpdk 2>&1)
$(info TEEEE=$(TEEEE))
$(info -DMAX_CPUS=8)
$(info "########################################################################")



SRCS = core.c tcp_stream.c config.c api.c eventpoll.c socket.c pipe.c \
	   tcp_util.c eth_in.c ip_in.c tcp_in.c eth_out.c ip_out.c tcp_out.c \
	   arp.c timer.c cpu.c rss.c addr_pool.c fhash.c memory_mgt.c zc_memory_mgt.c logger.c debug.c \
	   tcp_rb_frag_queue.c zc_tcp_ring_buffer.c tcp_send_buffer.c u32hash.c zc_tcp_send_buffer.c zc_tcp_sb_queue.c tcp_sb_queue.c tcp_stream_queue.c \
	   io_module.c dpdk_module.c icmp.c


SRCS += intel_lthread/lthread.c  intel_lthread/lthread_cond.c  intel_lthread/lthread_diag.c \
		intel_lthread/lthread_mutex.c  intel_lthread/lthread_sched.c  intel_lthread/lthread_tls.c \
		intel_lthread/arch/aarch64/ctx.c schedule.c
INC  += -I./intel_lthread/ -I./intel_lthread/arch/aarch64/
GCC_OPT += -DEABLE_COROUTINE



OBJS = $(patsubst %.c,%.o,$(SRCS))
DEPS = $(patsubst %.c,.%.d,$(notdir $(SRCS)))

ifeq ($V,) # no echo
	export MSG=@echo
	export HIDE=@
else
	export MSG=@\#
	export HIDE=
endif


### GOALS ###
all: default

default: $(OBJS) $(MTCP_HDR)
	mkdir -p $(MTCP_LIB_DIR)
	ar rvs $(MTCP_LIB_DIR)/$(MTCP_LIB) $(OBJS)

$(OBJS): %.o: %.c Makefile
	$(MSG) "   CC $<"
	$(HIDE) $(GCC) $(CFLAGS) $(GCC_OPT) $(INC) -c $< -o $@
$(DEPS): .%.d: %.c Makefile
	$(HIDE) $(GCC) $(GCC_OPT) $(INC) -MM $(CFLAGS) $< > $@

-include $(DEPS)

$(MTCP_HDR):
	cp $(INC_DIR)/$@ $(MTCP_HDR_DIR)/$@

clean: clean-library
	$(MSG) "   CLEAN *.o's"
	$(HIDE) rm -f *.o *~ core
	$(MSG) "   CLEAN *.d's"
	$(HIDE) rm -f .*.d

clean-library:
	$(MSG) "   CLEAN *.a"
	$(HIDE) rm -f $(MTCP_LIB_DIR)/*
	$(MSG) "   CLEAN *.h"
	$(HIDE) rm -f $(MTCP_HDR_DIR)/*

distclean: clean
	rm -f Makefile
