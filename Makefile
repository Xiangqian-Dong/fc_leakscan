topdir=$(abspath .)

incdir= -I${topdir}/ -I${topdir}/include -I/usr/local/include
linkdir=-L${topdir}/lib -L/lib64/mysql
# link= -lmysqlclient -lmuduo_base -lmuduo_net
# link= -lmysqlclient -lmuduo_base_cpp11 -lmuduo_net_cpp11
link= -levent
# CXXFLAGS :=-pthread -DMUDUO_STD_STRING #-Wshadow
# CXXFLAGS=-DMUDUO_STD_STRING #-Wshadow

ifeq ($(PDEBUG), 1)
	CXXFLAGS += -DPDEBUG
endif

OS_VER := $(shell uname -r | cut -d "." -f 4)

CXXFLAGS += -g -O0 -Wall 
ifeq ($(OS_VER),el6)
	CXXFLAGS += -std=c++0x
else
	CXXFLAGS += -std=c++11
endif

# filtermc :=  ${topdir}/mc_client.o ${topdir}/mc_web.o
# filtermcclient :=  ${topdir}/main.o ${topdir}/mc_web.o
# filtermcweb :=  ${topdir}/main.o ${topdir}/mc_client.o

srclist := $(wildcard ${topdir}/*.cc)
srclist1 := $(wildcard ${topdir}/*.c)
OBJ1 := $(patsubst %.cc, %.o, ${srclist})
OBJ1 += $(patsubst %.c, %.o, ${srclist1})
# OBJ1 := $(patsubst %.cc, %.o, $(wildcard ${topdir}/*.cc))
#OBJ1 += $(patsubst %.cc, %.o, $(wildcard ${topdir}/base/*.cc))
# kmcobj := $(filter-out $(filterkmc), $(OBJ1))
# mcobj := $(filter-out $(filtermc), $(OBJ1))
# mcclientobj := $(filter-out $(filtermcclient), $(OBJ1))
# mcwebobj := $(filter-out $(filtermcweb), $(OBJ1))

all :  fc_leakscan

fc_leakscan: $(OBJ1)
	g++ ${CXXFLAGS} ${incdir} -o $@ $^ ${linkdir} ${link}

# mcclient: $(mcclientobj)
# 	g++ ${CXXFLAGS} ${incdir} -o $@ $^ ${linkdir} ${link}

# mcweb: $(mcwebobj)
# 	g++ ${CXXFLAGS} ${incdir} -o $@ $^ ${linkdir} ${link}

%.o: %.cc
	g++ ${CXXFLAGS} ${incdir} -c -o $@ $^ 

clean:
	rm -fr  fc_leakscan $(OBJ1)

pkg:
	cp $(prom) package/srv/bin
	cd package&&tar cvzf ../fc_leakscan_bin.tar.gz *