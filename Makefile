CXXFLAGS := -Wall -Wextra -Werror -O2 -Iinclude -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -std=c++11
LDFLAGS := lib/*.o -lcryptopp -pie
SRC := src/Scrypt.cc src/Decrypt.cc src/Encrypt.cc src/Utils.cc
OBJS := $(addprefix obj/, $(addsuffix .o, $(basename $(notdir $(SRC)))))

all: lib folders fcrypt

lib:
	@echo "[SCRYPT] Compiling and copying in lib/"
	@./scripts/copy_scrypt.sh
folders:
	@mkdir -p bin obj

fcrypt_test: $(OBJS) obj/test.o
	@echo "[LD]  $@"
	@$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o bin/$@ 

fcrypt: $(OBJS) obj/main.o
	@echo "[LD]  $@"
	@$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o bin/$@ 

obj/%.o: src/%.cc
	@echo "[CXX] $^"
	@$(CXX) -c $(CXXFLAGS) $< -o $@

clean:
	rm -rf bin obj lib

install:
	cp bin/fcrypt /usr/bin/fcrypt

.PHONY: clean install folders
.NOTPARALLEL: lib folders
