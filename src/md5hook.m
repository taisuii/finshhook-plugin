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
static UITextView *logTextView = nil;
static BOOL isWindowHidden = NO;
static BOOL isPaused = NO;
static BOOL isMinimized = NO;
static UILabel *statusLabel = nil;
static UIButton *pauseButton = nil;
static UIButton *minimizeButton = nil;
static UILabel *pathLabel = nil;
static CGRect originalWindowFrame = {{0, 0, 0, 0}};
static UIView *titleBarView = nil;

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
        // 地址部分
        [result appendFormat:@"%04lx: ", (unsigned long)offset];

        // Hex 部分
        for (NSUInteger i = 0; i < 16; i++) {
            if (offset + i < len) {
                [result appendFormat:@"%02x ", bytes[offset + i]];
            } else {
                [result appendString:@"   "];
            }
            if (i == 7) [result appendString:@" "];
        }

        [result appendString:@" |"];

        // ASCII 部分
        for (NSUInteger i = 0; i < 16; i++) {
            if (offset + i < len) {
                unsigned char c = bytes[offset + i];
                if (c >= 32 && c < 127) {
                    [result appendFormat:@"%c", c];
                } else {
                    [result appendString:@"."];
                }
            }
        }

        [result appendString:@"|\n"];
    }

    return result;
}

static void save_to_file(NSString *timestamp, NSString *utf8Str, NSString *hexStr, NSString *md5, NSData *inputData, NSString *callStack) {
    NSString *logPath = get_log_file_path();

    // 格式化日志条目
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

    // 写入文件（追加模式）
    NSError *error = nil;
    if ([[NSFileManager defaultManager] fileExistsAtPath:logPath]) {
        // 追加内容
        NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:logPath];
        [fileHandle seekToEndOfFile];
        [fileHandle writeData:[entry dataUsingEncoding:NSUTF8StringEncoding]];
        [fileHandle closeFile];
    } else {
        // 创建新文件
        [entry writeToFile:logPath
               atomically:YES
                 encoding:NSUTF8StringEncoding
                    error:&error];
    }

    if (error) {
        NSLog(@"[MD5-HOOK] 写入日志文件失败: %@", error.localizedDescription);
    }
}

// ---------- 日志追加函数 ----------
static void append_log(NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!logTextView) return;

        NSString *timestamp = [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                               dateStyle:NSDateFormatterNoStyle
                                                               timeStyle:NSDateFormatterMediumStyle];
        NSString *fullMessage = [NSString stringWithFormat:@"[%@] %@\n", timestamp, message];

        logTextView.text = [logTextView.text stringByAppendingString:fullMessage];
        NSLog(@"[MD5-HOOK] %@", message);

        // 只有在未暂停时才自动滚动
        if (!isPaused && logTextView.text.length > 0) {
            NSRange bottom = NSMakeRange(logTextView.text.length - 1, 1);
            [logTextView scrollRangeToVisible:bottom];
        }
    });
}

// --------- 拖动支持（UIWindow Category） ---------
@interface UIWindow (MD5Hook)
- (void)handlePan:(UIPanGestureRecognizer *)g;
- (void)handleLongPress:(UILongPressGestureRecognizer *)g;
- (void)clearLog;
- (void)togglePause;
- (void)toggleMinimize;
@end

@implementation UIWindow (MD5Hook)
- (void)handlePan:(UIPanGestureRecognizer *)g {
    if (g.state == UIGestureRecognizerStateChanged) {
        CGPoint delta = [g translationInView:self.superview ?: self];
        self.center = CGPointMake(self.center.x + delta.x,
                                  self.center.y + delta.y);
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

- (void)clearLog {
    [[NSNotificationCenter defaultCenter] postNotificationName:@"MD5HookClearLog" object:nil];
}

- (void)togglePause {
    isPaused = !isPaused;
    if (pauseButton) {
        [pauseButton setTitle:isPaused ? @"继续" : @"暂停" forState:UIControlStateNormal];
        pauseButton.backgroundColor = isPaused ?
            [UIColor colorWithRed:0.2 green:0.6 blue:0.2 alpha:1.0] :
            [UIColor colorWithRed:0.6 green:0.4 blue:0.2 alpha:1.0];
    }
    if (statusLabel) {
        statusLabel.text = isPaused ? @"⏸️ 已暂停" : @"▶️ 运行中";
    }
    if (isPaused) {
        append_log(@"日志已暂停 - 文件仍在保存中");
    } else {
        append_log(@"日志已继续");
    }
}

- (void)toggleMinimize {
    isMinimized = !isMinimized;

    // 保存原始尺寸和位置，第一次最小化时
    if (!isMinimized && CGRectIsNull(originalWindowFrame)) {
        originalWindowFrame = self.frame;
    }

    CGFloat animationDuration = 0.3;

    if (isMinimized) {
        // 最小化 - 只保留标题栏高度
        [UIView animateWithDuration:animationDuration animations:^{
            self.frame = CGRectMake(self.frame.origin.x,
                                  self.frame.origin.y,
                                  self.frame.size.width,
                                  50); // 只保留标题栏
        }];

        // 隐藏内容区域
        [logTextView setAlpha:0];
        if (pathLabel) {
            [pathLabel setAlpha:0];
        }
    } else {
        // 恢复
        if (!CGRectIsNull(originalWindowFrame)) {
            [UIView animateWithDuration:animationDuration animations:^{
                self.frame = originalWindowFrame;
            }];

            // 显示内容区域
            [logTextView setAlpha:1];
            if (pathLabel) {
                [pathLabel setAlpha:1];
            }
        }
    }

    if (minimizeButton) {
        [minimizeButton setTitle:isMinimized ? @"恢复" : @"最小化" forState:UIControlStateNormal];
        minimizeButton.backgroundColor = isMinimized ?
            [UIColor colorWithRed:0.5 green:0.5 blue:0.8 alpha:1.0] :
            [UIColor colorWithRed:0.5 green:0.5 blue:0.5 alpha:1.0];
    }
}
@end

// ---------- 设置悬浮窗 ----------
static void setup_float_window(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (floatWindow) return;

        CGRect screenBounds = [UIScreen mainScreen].bounds;
        CGFloat windowWidth = MIN(screenBounds.size.width, 380);
        CGFloat windowHeight = MIN(screenBounds.size.height * 0.45, 360);
        CGFloat windowX = screenBounds.size.width - windowWidth - 10;
        CGFloat windowY = 100;

        // 创建悬浮窗
        floatWindow = [[UIWindow alloc] initWithFrame:CGRectMake(windowX, windowY, windowWidth, windowHeight)];
        originalWindowFrame = floatWindow.frame;
        floatWindow.windowLevel = UIWindowLevelAlert + 1000;
        floatWindow.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.95];
        floatWindow.layer.cornerRadius = 12;
        floatWindow.layer.masksToBounds = YES;
        floatWindow.layer.borderWidth = 1;
        floatWindow.layer.borderColor = [[UIColor colorWithWhite:0.25 alpha:1.0] CGColor];

        // 添加标题栏
        UIView *titleBar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, windowWidth, 50)];
        titleBar.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1.0];
        titleBarView = titleBar;
        [floatWindow addSubview:titleBar];

        // 标题标签
        UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 5, 140, 20)];
        titleLabel.text = @"🔑 MD5 Hook";
        titleLabel.textColor = [UIColor greenColor];
        titleLabel.font = [UIFont boldSystemFontOfSize:13];
        [titleBar addSubview:titleLabel];

        // 状态标签（显示文件路径和运行状态）
        statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 25, windowWidth - 20, 20)];
        statusLabel.text = @"▶️ 运行中";
        statusLabel.textColor = [UIColor colorWithWhite:0.7 alpha:1.0];
        statusLabel.font = [UIFont systemFontOfSize:9];
        [titleBar addSubview:statusLabel];

        // 最小化按钮
        minimizeButton = [UIButton buttonWithType:UIButtonTypeSystem];
        minimizeButton.frame = CGRectMake(windowWidth - 200, 5, 45, 20);
        [minimizeButton setTitle:@"最小化" forState:UIControlStateNormal];
        [minimizeButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        minimizeButton.titleLabel.font = [UIFont boldSystemFontOfSize:10];
        minimizeButton.backgroundColor = [UIColor colorWithRed:0.5 green:0.5 blue:0.5 alpha:1.0];
        minimizeButton.layer.cornerRadius = 4;
        [minimizeButton addTarget:floatWindow action:@selector(toggleMinimize) forControlEvents:UIControlEventTouchUpInside];
        [titleBar addSubview:minimizeButton];

        // 暂停按钮
        pauseButton = [UIButton buttonWithType:UIButtonTypeSystem];
        pauseButton.frame = CGRectMake(windowWidth - 150, 5, 45, 20);
        [pauseButton setTitle:@"暂停" forState:UIControlStateNormal];
        [pauseButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        pauseButton.titleLabel.font = [UIFont boldSystemFontOfSize:10];
        pauseButton.backgroundColor = [UIColor colorWithRed:0.6 green:0.4 blue:0.2 alpha:1.0];
        pauseButton.layer.cornerRadius = 4;
        [pauseButton addTarget:floatWindow action:@selector(togglePause) forControlEvents:UIControlEventTouchUpInside];
        [titleBar addSubview:pauseButton];

        // 清空按钮
        UIButton *clearButton = [UIButton buttonWithType:UIButtonTypeSystem];
        clearButton.frame = CGRectMake(windowWidth - 100, 5, 45, 20);
        [clearButton setTitle:@"清空" forState:UIControlStateNormal];
        [clearButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        clearButton.titleLabel.font = [UIFont boldSystemFontOfSize:10];
        clearButton.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.2 alpha:1.0];
        clearButton.layer.cornerRadius = 4;
        [clearButton addTarget:floatWindow action:@selector(clearLog) forControlEvents:UIControlEventTouchUpInside];
        [titleBar addSubview:clearButton];

        // 路径标签 - 显示在悬浮窗底部
        NSString *logPath = get_log_file_path();
        pathLabel = [[UILabel alloc] initWithFrame:CGRectMake(5, windowHeight - 20, windowWidth - 10, 15)];
        pathLabel.text = [NSString stringWithFormat:@"📁 %@", logPath];
        pathLabel.textColor = [UIColor colorWithWhite:0.5 alpha:1.0];
        pathLabel.font = [UIFont fontWithName:@"Menlo" size:8];
        pathLabel.adjustsFontSizeToFitWidth = YES;
        pathLabel.minimumScaleFactor = 0.5;
        [floatWindow addSubview:pathLabel];

        // 日志文本视图
        logTextView = [[UITextView alloc] initWithFrame:CGRectMake(5, 55, windowWidth - 10, windowHeight - 80)];
        logTextView.backgroundColor = [UIColor clearColor];
        logTextView.textColor = [UIColor greenColor];
        logTextView.font = [UIFont fontWithName:@"Menlo" size:10];
        logTextView.editable = NO;
        logTextView.selectable = YES;
        logTextView.textContainerInset = UIEdgeInsetsMake(5, 5, 5, 5);
        [floatWindow addSubview:logTextView];

        // 添加拖动手势
        UIPanGestureRecognizer *panGesture = [[UIPanGestureRecognizer alloc] initWithTarget:floatWindow action:@selector(handlePan:)];
        [titleBar addGestureRecognizer:panGesture];

        // 添加长按手势（隐藏/显示）
        UILongPressGestureRecognizer *longPressGesture = [[UILongPressGestureRecognizer alloc] initWithTarget:floatWindow action:@selector(handleLongPress:)];
        longPressGesture.minimumPressDuration = 0.5;
        [titleBar addGestureRecognizer:longPressGesture];

        // 注册清空日志通知 - 使用 block
        [[NSNotificationCenter defaultCenter] addObserverForName:@"MD5HookClearLog"
                                                           object:nil
                                                            queue:[NSOperationQueue mainQueue]
                                                       usingBlock:^(NSNotification *notif) {
            if (logTextView) {
                logTextView.text = @"";
            }
        }];

        // 显示悬浮窗
        floatWindow.hidden = NO;

        append_log(@"悬浮窗已启动 ✓");
        append_log(@"提示: 拖动标题栏移动, 长按隐藏, 暂停可防止刷屏");
        append_log([NSString stringWithFormat:@"日志文件: %@", logPath]);
    });
}


// ---------- Hook CC_MD5（一次性计算，最常见） ----------
static unsigned char *hooked_CC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    // 过滤短输入（低于 72 字节不 Hook）
    if (len < 72) {
        return orig_CC_MD5(data, len, md);
    }

    unsigned char *result = orig_CC_MD5(data, len, md);

    // 打印明文（保留完整数据）
    NSData  *inputData  = [NSData dataWithBytes:data length:len];
    NSMutableString *hex = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", md[i]];

    // 处理UTF-8解码和Hex格式
    NSString *inputStr = [[NSString alloc] initWithData:inputData encoding:NSUTF8StringEncoding];
    NSString *hexStr = data_to_hex(inputData);

    // 如果UTF-8解码失败，显示Hex格式作为主要显示
    if (!inputStr) {
        inputStr = hexStr;
    }

    NSString *timestamp = [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                           dateStyle:NSDateFormatterNoStyle
                                                           timeStyle:NSDateFormatterMediumStyle];

    // 获取调用堆栈
    NSArray *stackSymbols = [NSThread callStackSymbols];
    NSMutableString *callStack = [NSMutableString string];
    for (NSString *symbol in stackSymbols) {
        // 过滤掉系统框架的调用，只保留应用的
        if ([symbol containsString:@"/var/mobile/Containers"]) {
            [callStack appendFormat:@"%@\n", symbol];
        }
    }

    // 始终保存到文件（即使暂停也保存）
    save_to_file(timestamp, inputStr, hexStr, hex, inputData, callStack);

    // 只有未暂停时才显示到悬浮窗
    if (!isPaused) {
        append_log([NSString stringWithFormat:@"IN UTF-8 (len=%u): %@", len, inputStr]);
        append_log([NSString stringWithFormat:@"IN HEX   (len=%u): %@", len, hexStr]);
        append_log([NSString stringWithFormat:@"MD5 RESULT: %@", hex]);
        if (callStack.length > 0) {
            append_log([NSString stringWithFormat:@"CALL STACK:\n%@", callStack]);
        }
        append_log(@"───────────────────────────────");
    }

    return result;
}

// ---------- Hook CC_MD5_Update（流式计算） ----------
static CC_LONG hooked_CC_MD5_Update(CC_MD5_CTX *c, const void *data, CC_LONG len) {
    NSData *chunk = [NSData dataWithBytes:data length:MIN(len, 256)];
    if (!isPaused) {
        append_log([NSString stringWithFormat:@"Update chunk (len=%u): %@", len, chunk]);
    }
    return orig_CC_MD5_Update(c, data, len);
}

// ---------- Hook CC_MD5_Final（流式最终结果） ----------
static int hooked_CC_MD5_Final(unsigned char *md, CC_MD5_CTX *c) {
    int ret = orig_CC_MD5_Final(md, c);
    NSMutableString *hex = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", md[i]];
    if (!isPaused) {
        append_log([NSString stringWithFormat:@"Final MD5: %@", hex]);
        append_log(@"───────────────────────────────");
    }
    return ret;
}

// ---------- 构造函数，dylib 加载时自动执行 ----------
__attribute__((constructor))
static void hook_init(void) {
    rebind_symbols((struct rebinding[]){
        {"CC_MD5",        hooked_CC_MD5,        (void **)&orig_CC_MD5},
        {"CC_MD5_Update", hooked_CC_MD5_Update,  (void **)&orig_CC_MD5_Update},
        {"CC_MD5_Final",  hooked_CC_MD5_Final,   (void **)&orig_CC_MD5_Final},
    }, 3);

    NSLog(@"[MD5-HOOK] fishhook 注入成功 ✓");

    // 设置悬浮窗
    setup_float_window();
}