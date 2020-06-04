cc = g++
cflags = -g -fPIC -I/usr/include/mysql
clibs = -lpthread -llog4c -levent
prom = fc_leakscan
deps = $(shell find ./ -maxdepth 1 -name "*.h")
src = $(shell find ./ -maxdepth 1 -name "*.c")
obj = $(src:%.c=%.o) 

$(prom): $(obj)
	$(cc) $(cflags) -o $(prom) $(obj) $(clibs)
	
%.o: %.c $(deps)
	$(cc) -c $(cflags) $< -o $@

clean:
	rm -rf $(obj) $(prom)

pkg:
	cp $(prom) log4crc package/srv/bin
	cp /usr/local/lib/libevent-2.1.so.7 package/usr/lib/
	cp /usr/local/lib/liblog4c.so.3 package/usr/lib/
	cd package&&tar cvzf ../fc_leakscan_bin.tar.gz *
	

