SDK     := $(shell xcrun --sdk iphoneos --show-sdk-path)
CC      := $(shell xcrun --find clang)
ARCH    := arm64
TARGET  := hook_md5.dylib
SRC     := src/fishhook.c src/md5hook.m

CFLAGS  := -arch $(ARCH) \
           -isysroot $(SDK) \
           -miphoneos-version-min=14.0 \
           -dynamiclib \
           -framework Foundation \
           -framework UIKit \
           -framework CoreGraphics \
           -ObjC \
           -Os

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)
	@echo "✅ 编译完成: $(TARGET)"

clean:
	rm -f $(TARGET)