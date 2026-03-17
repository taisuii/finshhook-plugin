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

static void save_to_file(NSString *timestamp, NSString *utf8Str, NSString *hexStr, NSString *md5) {
    NSString *logPath = get_log_file_path();

    // 格式化日志条目
    NSString *entry = [NSString stringWithFormat:
        @"----------------------------------------\n"
        @"时间: %@\n"
        @"长度: %lu\n"
        @"UTF-8明文:\n%@\n\n"
        @"Hex明文:\n%@\n\n"
        @"MD5结果:\n%@\n\n",
        timestamp,
        (unsigned long)utf8Str.length,
        utf8Str,
        hexStr,
        md5
    ];

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

        // 自动滚动到底部
        if (logTextView.text.length > 0) {
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
@end

// ---------- 设置悬浮窗 ----------
static void setup_float_window(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (floatWindow) return;

        CGRect screenBounds = [UIScreen mainScreen].bounds;
        CGFloat windowWidth = MIN(screenBounds.size.width, 360);
        CGFloat windowHeight = MIN(screenBounds.size.height * 0.4, 320);
        CGFloat windowX = screenBounds.size.width - windowWidth - 10;
        CGFloat windowY = 100;

        // 创建悬浮窗
        floatWindow = [[UIWindow alloc] initWithFrame:CGRectMake(windowX, windowY, windowWidth, windowHeight)];
        floatWindow.windowLevel = UIWindowLevelAlert + 1000;
        floatWindow.backgroundColor = [UIColor colorWithWhite:0.1 alpha:0.9];
        floatWindow.layer.cornerRadius = 10;
        floatWindow.layer.masksToBounds = YES;
        floatWindow.layer.borderWidth = 1;
        floatWindow.layer.borderColor = [[UIColor colorWithWhite:0.3 alpha:1.0] CGColor];

        // 添加标题栏
        UIView *titleBar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, windowWidth, 40)];
        titleBar.backgroundColor = [UIColor colorWithWhite:0.2 alpha:1.0];
        [floatWindow addSubview:titleBar];

        // 标题标签
        UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 5, 180, 30)];
        titleLabel.text = @"🔑 MD5 Hook";
        titleLabel.textColor = [UIColor greenColor];
        titleLabel.font = [UIFont boldSystemFontOfSize:14];
        [titleBar addSubview:titleLabel];

        // 清空按钮
        UIButton *clearButton = [UIButton buttonWithType:UIButtonTypeSystem];
        clearButton.frame = CGRectMake(windowWidth - 70, 5, 60, 30);
        [clearButton setTitle:@"清空" forState:UIControlStateNormal];
        [clearButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        clearButton.titleLabel.font = [UIFont systemFontOfSize:12];
        clearButton.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.2 alpha:1.0];
        clearButton.layer.cornerRadius = 5;
        [clearButton addTarget:floatWindow action:@selector(clearLog) forControlEvents:UIControlEventTouchUpInside];
        [titleBar addSubview:clearButton];

        // 日志文本视图
        logTextView = [[UITextView alloc] initWithFrame:CGRectMake(5, 45, windowWidth - 10, windowHeight - 50)];
        logTextView.backgroundColor = [UIColor clearColor];
        logTextView.textColor = [UIColor greenColor];
        logTextView.font = [UIFont fontWithName:@"Menlo" size:11];
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
        append_log(@"提示: 拖动标题栏移动位置, 长按标题栏隐藏/显示");
    });
}


// ---------- Hook CC_MD5（一次性计算，最常见） ----------
static unsigned char *hooked_CC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    // 过滤短输入（低于 48 字节不 Hook）
    if (len < 48) {
        return orig_CC_MD5(data, len, md);
    }

    unsigned char *result = orig_CC_MD5(data, len, md);

    // 打印明文（截断超长数据）
    NSData  *inputData  = [NSData dataWithBytes:data length:MIN(len, 256)];
    NSMutableString *hex = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", md[i]];

    NSString *inputStr = [[NSString alloc] initWithData:inputData encoding:NSUTF8StringEncoding];
    if (!inputStr) {
        inputStr = [inputData description];
    }

    NSString *timestamp = [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                           dateStyle:NSDateFormatterNoStyle
                                                           timeStyle:NSDateFormatterMediumStyle];
    NSString *hexStr = data_to_hex(inputData);

    // 保存到文件
    save_to_file(timestamp, inputStr, hexStr, hex);

    // 显示到悬浮窗
    append_log([NSString stringWithFormat:@"IN (len=%u): %@", len, inputStr]);
    append_log([NSString stringWithFormat:@"MD5: %@", hex]);
    append_log(@"───────────────────────────────");

    return result;
}

// ---------- Hook CC_MD5_Update（流式计算） ----------
static CC_LONG hooked_CC_MD5_Update(CC_MD5_CTX *c, const void *data, CC_LONG len) {
    NSData *chunk = [NSData dataWithBytes:data length:MIN(len, 256)];
    append_log([NSString stringWithFormat:@"Update chunk (len=%u): %@", len, chunk]);
    return orig_CC_MD5_Update(c, data, len);
}

// ---------- Hook CC_MD5_Final（流式最终结果） ----------
static int hooked_CC_MD5_Final(unsigned char *md, CC_MD5_CTX *c) {
    int ret = orig_CC_MD5_Final(md, c);
    NSMutableString *hex = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", md[i]];
    append_log([NSString stringWithFormat:@"Final MD5: %@", hex]);
    append_log(@"───────────────────────────────");
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