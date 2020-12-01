# ==========================================
#   Mostly taken from:
#   https://github.com/ThrowTheSwitch/Unity/tree/master/examples/example_2
#   http://www.throwtheswitch.org/build/make
# ==========================================

include component.mk
#We try to detect the OS we are running on, and adjust commands as needed
ifeq ($(OSTYPE),cygwin)
	CLEANUP = rm -f
	CLEANUP_DIR = rm -rf
	MKDIR = mkdir -p
	TARGET_EXTENSION=.out
elseifeq ($(OSTYPE),msys)
	CLEANUP = rm -f
	CLEANUP_DIR = rm -rf
	MKDIR = mkdir -p
	TARGET_EXTENSION=.exe
elseifeq ($(OS),Windows_NT)
	CLEANUP = del /F /Q
	MKDIR = mkdir
	TARGET_EXTENSION=.exe
else
	CLEANUP = rm -f
	CLEANUP_DIR = rm -rf
	MKDIR = mkdir -p
	TARGET_EXTENSION=.out
endif

COMPILE=gcc

CFLAGS = -std=c99
#CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Werror 
CFLAGS += -Wpointer-arith
CFLAGS += -Wcast-align
CFLAGS += -Wwrite-strings
#CFLAGS += -Wswitch-default
CFLAGS += -Wunreachable-code
CFLAGS += -Winit-self
CFLAGS += -Wmissing-field-initializers
CFLAGS += -Wno-unknown-pragmas
CFLAGS += -Wstrict-prototypes
CFLAGS += -Wundef
CFLAGS += -Wold-style-definition
CFLAGS += -Wmissing-prototypes
CFLAGS += -Wmissing-declarations
CFLAGS += -DUNITY_FIXTURES

#CFLAGS += -Wno-unused-parameter

#####################################################
# PATHS
#####################################################

# libraries
APP_LIBRARIES = sodium noiseprotocol

#unity
PATH_UNITY_ROOT=libs/Unity/

#noise-c
PATH_NOISE_ROOT=libs/noise-c/

#app
PATH_APP_SRC = $(COMPONENT_SRCDIRS)
PATH_APP_INC = $(COMPONENT_ADD_INCLUDEDIRS) $(COMPONENT_PRIV_INCLUDEDIRS) $(PATH_NOISE_ROOT)build/include/ 
        
#tests
PATH_TEST_SRC = tests/
PATH_TEST_RUNNERS = $(PATH_TEST_SRC)runner/

#NOISE_SYMBOLS= USE_SODIUM=1 USE_LIBSODIUM=1 USE_OPENSSL=0

#Directories to create
PATH_BUILD          = build/
PATH_BUILD_RESULTS  = $(PATH_BUILD)results/
PATH_BUILD_OBJS     = $(PATH_BUILD)objs/ #TODO
PATH_BUILD_DEPENDS  = $(PATH_BUILD)depends/ #TODO
PATH_DOCS           = docs/

#Variable used during build call
BUILD_THE_PATHS     =\
   $(PATH_BUILD) \
   $(PATH_BUILD_RESULTS) \
   $(PATH_BUILD_OBJS) \
   $(PATH_BUILD_DEPENDS)

#####################################################
# SOURCE CODE
#####################################################
SOURCE_TEST = $(wildcard $(PATH_TEST_SRC)*.c)
SOURCE_TEST_RUNNERS = $(wildcard $(PATH_TEST_RUNNERS)*.c)
SOURCE_APP = $(foreach src_dir, $(PATH_APP_SRC), $(wildcard $(src_dir)/*.c)) #$(wildcard $(scr_dir)/*.c)
APP_INC_DIRS = $(foreach inc_dir, $(PATH_APP_INC), -I$(inc_dir))
LIBRARY_FLAGS = -L$(PATH_NOISE_ROOT)build/lib/ $(foreach lib, $(APP_LIBRARIES), -l$(lib))

#####################################################
# RESULTS 
#####################################################
RESULTS_TEST = $(PATH_BUILD_RESULTS)results_tests.txt

TARGET_BASE1=all_tests
TARGET1 = $(PATH_BUILD)$(TARGET_BASE1)$(TARGET_EXTENSION)
SRC_FILES1=\
  $(PATH_UNITY_ROOT)src/unity.c \
  $(PATH_UNITY_ROOT)extras/fixture/src/unity_fixture.c \
  $(SOURCE_APP) \
  $(SOURCE_TEST) \
  $(SOURCE_TEST_RUNNERS)

INC_DIRS= -I$(PATH_UNITY_ROOT)src \
	-I$(PATH_UNITY_ROOT)extras/fixture/src \
	-I$(PATH_UNITY_ROOT)extras/memory/src \
	$(APP_INC_DIRS)
SYMBOLS= $(foreach sym, $(NOISE_SYMBOLS), -D$(sym))

all: clean default print

debug:
	@echo "$(RESULTS_TEST)"

RESULTS=$(RESULTS_TEST)

default:$(BUILD_THE_PATHS) $(RESULTS)

$(PATH_BUILD):
	$(MKDIR) $(PATH_BUILD)

$(PATH_BUILD_RESULTS):
	$(MKDIR) $(PATH_BUILD_RESULTS)

$(PATH_BUILD_OBJS):
	$(MKDIR) $(PATH_BUILD_OBJS)

$(PATH_BUILD_DEPENDS):
	$(MKDIR) $(PATH_BUILD_DEPENDS)

$(RESULTS_TEST):
	$(COMPILE) $(CFLAGS) $(INC_DIRS) $(SYMBOLS) -g $(SRC_FILES1) $(LIBRARY_FLAGS) -o $(TARGET1)
	./$(TARGET1) -v > $@ 2>&1

.PHONEY:print
print:
	@echo "=============\nRUNNING TESTS:\n============="
	@echo "-------------\nIGNORES:\n--------------"
	@grep IGNORE $(RESULTS_TEST) || true
	@echo "-------------\nFAILURES:\n--------------"
	@grep FAIL $(RESULTS_TEST) || true
	@echo "-------------\nSUCCESSES:\n--------------"
	@grep PASS $(RESULTS_TEST) || true
	@echo "\nDONE"

.PHONEY:clean
clean:
	$(CLEANUP_DIR) $(PATH_BUILD)


noise-config:
	$(MKDIR) $(PATH_NOISE_ROOT)build
	cd $(PATH_NOISE_ROOT) && autoreconf -i && ./configure --prefix=$(CURDIR)/$(PATH_NOISE_ROOT)build --with-libsodium
noise-install: noise-config
	cd $(PATH_NOISE_ROOT) && make install
noise-clean:
	cd $(PATH_NOISE_ROOT) && make distclean