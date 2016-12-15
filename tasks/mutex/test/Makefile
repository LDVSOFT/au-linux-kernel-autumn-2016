include ../sub_config.mk

BIN_DIR=./bin/
SRC_DIR=./src/
MUTEX_LIB_DIR=../mutex_lib/
LIB_MUTEX_INCLUDE_DIR=../mutex_lib/include/
AU_BENCH_BIN=$(BIN_DIR)/au_bench
PTHREAD_BENCH_BIN=$(BIN_DIR)/pthread_bench
TEST_BIN=$(BIN_DIR)/test

CFLAGS=-static
LIBS=-L$(MUTEX_LIB_DIR)/bin/ -lmutex -pthread
INCLUDES=-I$(LIB_MUTEX_INCLUDE_DIR) \
	   -I../mutex_module/

all: $(AU_BENCH_BIN) $(PTHREAD_BENCH_BIN) $(TEST_BIN)

$(AU_BENCH_BIN): $(SRC_DIR)/bench.c
	gcc $< $(CFLAGS) $(LIBS) $(INCLUDES) -DUSE_AU_MUTEX -o $@
	cp $@ $(VM_SHARE_PATH)

$(PTHREAD_BENCH_BIN): $(SRC_DIR)/bench.c
	gcc $< $(CFLAGS) $(LIBS) $(INCLUDES) -o $@
	cp $@ $(VM_SHARE_PATH)

$(TEST_BIN): $(SRC_DIR)/test.c
	gcc $< $(CFLAGS) $(LIBS) $(INCLUDES) -o $@
	cp $@ $(VM_SHARE_PATH)

clean:
	rm -rf $(BIN_DIR)/*

.PHONY: clean
