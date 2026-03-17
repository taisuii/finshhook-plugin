#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <UIKit/UIKit.h>
#import "fishhook.h"

// 保存原始函数指针
static unsigned char *(*orig_CC_MD5)(const void *data, CC_LONG len, unsigned char *md);
static CC_LONG       (*orig_CC_MD5_Update)(CC_MD5_CTX *c, const void *data, CC_LONG len);
static int           (*orig_CC_MD5_Final)(unsigned char *md, CC_MD5_CTX *c);

// ---------- 悬浮窗全局变量 ----------
static UIWindow *floatWindow = nil;
static BOOL isWindowHidden = NO;
static UILabel *statusLabel = nil;
static UIButton *clearButton = nil;

// ---------- 日志文件保存函数 ----------
static NSString *get_log_file_path(void) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docDir = paths.firstObject;
    return [docDir stringByAppendingPathComponent:@"md5hook.log"];
}

static NSString *data_to_hex(NSData *data) {
    NSMutableString *hex = [NSMutableString string];
    const unsigned char *bytes = [data bytes];

    for (NSUInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return hex;
}

// 生成 HexDump 格式的字符串
static NSString *hex_dump_format(NSData *data) {
    if (!data) return @"";

    NSMutableString *result = [NSMutableString string];
    const unsigned char *bytes = [data bytes];
    NSUInteger len = data.length;

    for (NSUInteger offset = 0; offset < len; offset += 16) {
        [result appendFormat:@"%04lx: ", (unsigned long)offset];
        for (NSUInteger i = 0; i < 16; i++) {
            if (offset + i < len) {
                [result appendFormat:@"%02x ", bytes[offset + i]];
            } else {
                [result appendString:@"   "];
            }
            if (i == 7) [result appendString:@" "];
        }
        [result appendString:@" |"];
        for (NSUInteger i = 0; i < 16; i++) {
            if (offset + i < len) {
                unsigned char c = bytes[offset + i];
                [result appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
            }
        }
        [result appendString:@"|\n"];
    }

    return result;
}

static void save_to_file(NSString *timestamp, NSString *utf8Str, NSString *hexStr, NSString *md5, NSData *inputData, NSString *callStack) {
    NSString *logPath = get_log_file_path();
    NSMutableString *entry = [NSMutableString string];
    [entry appendString:@"----------------------------------------\n"];
    [entry appendFormat:@"时间: %@\n", timestamp];
    [entry appendFormat:@"长度: %lu\n", (unsigned long)inputData.length];
    [entry appendString:@"\nUTF-8明文:\n"];
    [entry appendFormat:@"%@\n\n", utf8Str];
    [entry appendString:@"Hex (连续):\n"];
    [entry appendFormat:@"%@\n\n", hexStr];
    [entry appendString:@"HexDump (格式):\n"];
    [entry appendFormat:@"%@\n", hex_dump_format(inputData)];
    [entry appendString:@"MD5结果:\n"];
    [entry appendFormat:@"%@\n", md5];
    if (callStack.length > 0) {
        [entry appendFormat:@"调用堆栈:\n%@", callStack];
    }
    [entry appendString:@"\n\n"];

    NSError *error = nil;
    if ([[NSFileManager defaultManager] fileExistsAtPath:logPath]) {
        NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:logPath];
        [fileHandle seekToEndOfFile];
        [fileHandle writeData:[entry dataUsingEncoding:NSUTF8StringEncoding]];
        [fileHandle closeFile];
    } else {
        [entry writeToFile:logPath
               atomically:YES
                 encoding:NSUTF8StringEncoding
                    error:&error];
    }

    if (error) {
        NSLog(@"[MD5-HOOK] 写入日志文件失败: %@", error.localizedDescription);
    }
}

// --------- UIWindow 分类 ---------
@interface UIWindow (MD5Hook)
- (void)handlePan:(UIPanGestureRecognizer *)g;
- (void)handleLongPress:(UILongPressGestureRecognizer *)g;
- (void)clearAll;
@end

@implementation UIWindow (MD5Hook)
- (void)handlePan:(UIPanGestureRecognizer *)g {
    if (g.state == UIGestureRecognizerStateChanged) {
        CGPoint delta = [g translationInView:self.superview ?: self];
        self.center = CGPointMake(self.center.x + delta.x, self.center.y + delta.y);
        [g setTranslation:CGPointMake(0, 0) inView:self.superview ?: self];
    }
}

- (void)handleLongPress:(UILongPressGestureRecognizer *)g {
    if (g.state == UIGestureRecognizerStateBegan) {
        isWindowHidden = !isWindowHidden;
        [UIView animateWithDuration:0.3 animations:^{
            self.alpha = isWindowHidden ? 0.1 : 1.0;
        }];
    }
}

- (void)clearAll {
    // 删除文件
    NSString *logPath = get_log_file_path();
    if ([[NSFileManager defaultManager] fileExistsAtPath:logPath]) {
        NSError *error = nil;
        [[NSFileManager defaultManager] removeItemAtPath:logPath error:&error];
        if (error) {
            NSLog(@"[MD5-HOOK] 删除日志文件失败: %@", error.localizedDescription);
        } else {
            NSLog(@"[MD5-HOOK] 日志文件已删除");
        }
    }
}
@end

// ---------- 设置悬浮窗 ----------
static void setup_float_window(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (floatWindow) return;

        CGRect screenBounds = [UIScreen mainScreen].bounds;
        CGFloat windowWidth = 240;
        CGFloat windowHeight = 80;
        CGFloat windowX = screenBounds.size.width - windowWidth - 10;
        CGFloat windowY = 100;

        floatWindow = [[UIWindow alloc] initWithFrame:CGRectMake(windowX, windowY, windowWidth, windowHeight)];
        floatWindow.windowLevel = UIWindowLevelAlert + 1000;
        floatWindow.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.95];
        floatWindow.layer.cornerRadius = 12;
        floatWindow.layer.masksToBounds = YES;
        floatWindow.layer.borderWidth = 1;
        floatWindow.layer.borderColor = [[UIColor colorWithWhite:0.25 alpha:1.0] CGColor];

        UIView *titleBar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, windowWidth, 50)];
        titleBar.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1.0];
        [floatWindow addSubview:titleBar];

        UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 15, 140, 20)];
        titleLabel.text = @"🔑 MD5 Hook";
        titleLabel.textColor = [UIColor greenColor];
        titleLabel.font = [UIFont boldSystemFontOfSize:13];
        [titleBar addSubview:titleLabel];

        statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 55, windowWidth - 20, 20)];
        statusLabel.text = @"▶️ 运行中";
        statusLabel.textColor = [UIColor colorWithWhite:0.7 alpha:1.0];
        statusLabel.font = [UIFont systemFontOfSize:10];
        [floatWindow addSubview:statusLabel];

        clearButton = [UIButton buttonWithType:UIButtonTypeSystem];
        clearButton.frame = CGRectMake(windowWidth - 60, 15, 45, 20);
        [clearButton setTitle:@"清空" forState:UIControlStateNormal];
        [clearButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        clearButton.titleLabel.font = [UIFont boldSystemFontOfSize:10];
        clearButton.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.2 alpha:1.0];
        clearButton.layer.cornerRadius = 4;
        [clearButton addTarget:floatWindow action:@selector(clearAll) forControlEvents:UIControlEventTouchUpInside];
        [titleBar addSubview:clearButton];

        UIPanGestureRecognizer *panGesture = [[UIPanGestureRecognizer alloc] initWithTarget:floatWindow action:@selector(handlePan:)];
        [titleBar addGestureRecognizer:panGesture];

        UILongPressGestureRecognizer *longPressGesture = [[UILongPressGestureRecognizer alloc] initWithTarget:floatWindow action:@selector(handleLongPress:)];
        longPressGesture.minimumPressDuration = 0.5;
        [titleBar addGestureRecognizer:longPressGesture];

        NSString *logPath = get_log_file_path();
        UILabel *pathLabel = [[UILabel alloc] initWithFrame:CGRectMake(5, 75, windowWidth - 10, 15)];
        pathLabel.text = [NSString stringWithFormat:@"📁 %@", logPath];
        pathLabel.textColor = [UIColor colorWithWhite:0.5 alpha:1.0];
        pathLabel.font = [UIFont fontWithName:@"Menlo" size:7];
        pathLabel.adjustsFontSizeToFitWidth = YES;
        pathLabel.minimumScaleFactor = 0.5;
        [floatWindow addSubview:pathLabel];

        floatWindow.hidden = NO;
        NSLog(@"[MD5-HOOK] 悬浮窗已启动");
    });
}

// ---------- Hook CC_MD5 ----------
static unsigned char *hooked_CC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    if (len < 72) {
        return orig_CC_MD5(data, len, md);
    }

    unsigned char *result = orig_CC_MD5(data, len, md);
    NSData *inputData = [NSData dataWithBytes:data length:len];
    NSMutableString *hex = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", md[i]];

    NSString *inputStr = [[NSString alloc] initWithData:inputData encoding:NSUTF8StringEncoding];
    if (!inputStr) {
        inputStr = [inputData description];
    }
    NSString *hexStr = data_to_hex(inputData);
    NSString *timestamp = [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                       dateStyle:NSDateFormatterNoStyle
                                                       timeStyle:NSDateFormatterMediumStyle];

    NSArray *stackSymbols = [NSThread callStackSymbols];
    NSMutableString *callStack = [NSMutableString string];
    for (NSString *symbol in stackSymbols) {
        if ([symbol containsString:@"/var/mobile/Containers"]) {
            [callStack appendFormat:@"%@\n", symbol];
        }
    }

    save_to_file(timestamp, inputStr, hexStr, hex, inputData, callStack);

    return result;
}

// ---------- Hook CC_MD5_Update ----------
static CC_LONG hooked_CC_MD5_Update(CC_MD5_CTX *c, const void *data, CC_LONG len) {
    return orig_CC_MD5_Update(c, data, len);
}

// ---------- Hook CC_MD5_Final ----------
static int hooked_CC_MD5_Final(unsigned char *md, CC_MD5_CTX *c) {
    return orig_CC_MD5_Final(md, c);
}

// ---------- 构造函数 ----------
__attribute__((constructor))
static void hook_init(void) {
    rebind_symbols((struct rebinding[]){
        {"CC_MD5",        hooked_CC_MD5,        (void **)&orig_CC_MD5},
        {"CC_MD5_Update", hooked_CC_MD5_Update,  (void **)&orig_CC_MD5_Update},
        {"CC_MD5_Final",  hooked_CC_MD5_Final,   (void **)&orig_CC_MD5_Final},
    }, 3);

    NSLog(@"[MD5-HOOK] fishhook 注入成功");
    setup_float_window();
}