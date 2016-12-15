include ../sub_config.mk

BIN_DIR=./bin/
SRC_DIR=./src/
INCLUDE_DIR=./include/
MM_INCLUDE_DIR=../mutex_module/
LIB_NAME=libmutex
LIB_OBJ=$(BIN_DIR)/mutex_lib.o
LIB_SHARED=$(BIN_DIR)/$(LIB_NAME).so
LIB_STATIC=$(BIN_DIR)/$(LIB_NAME).a

INCLUDES=-I$(INCLUDE_DIR) -I$(MM_INCLUDE_DIR)
CFLAGS=-fPIC -lglibc

all: $(LIB_SHARED) $(LIB_STATIC)

$(LIB_STATIC): $(LIB_OBJ)
	ar rcs $@ $^
	cp $@ $(VM_SHARE_PATH)

$(LIB_SHARED): $(LIB_OBJ)
	gcc -shared $^ -o $@
	cp $@ $(VM_SHARE_PATH)

$(BIN_DIR)/%.o: $(SRC_DIR)/%.c \
	$(INCLUDE_DIR)/mutex.h \
	$(MM_INCLUDE_DIR)/shared_spinlock.h
	gcc -c $< $(CFLAGS) $(INCLUDES) -o $@

clean:
	rm -rf $(BIN_DIR)/*

.PHONY: clean all
