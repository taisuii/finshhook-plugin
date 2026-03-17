#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import "fishhook.h"

// 保存原始函数指针
static unsigned char *(*orig_CC_MD5)(const void *data, CC_LONG len, unsigned char *md);
static CC_LONG       (*orig_CC_MD5_Update)(CC_MD5_CTX *c, const void *data, CC_LONG len);
static int           (*orig_CC_MD5_Final)(unsigned char *md, CC_MD5_CTX *c);

// ---------- Hook CC_MD5（一次性计算，最常见） ----------
static unsigned char *hooked_CC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_MD5(data, len, md);

    // 打印明文（截断超长数据）
    NSData  *inputData  = [NSData dataWithBytes:data length:MIN(len, 256)];
    NSMutableString *hex = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", md[i]];

    NSLog(@"[MD5-HOOK] Input  (len=%u): %@", len,
          [[NSString alloc] initWithData:inputData encoding:NSUTF8StringEncoding] ?: inputData);
    NSLog(@"[MD5-HOOK] Digest : %@", hex);

    return result;
}

// ---------- Hook CC_MD5_Update（流式计算） ----------
static CC_LONG hooked_CC_MD5_Update(CC_MD5_CTX *c, const void *data, CC_LONG len) {
    NSData *chunk = [NSData dataWithBytes:data length:MIN(len, 256)];
    NSLog(@"[MD5-HOOK] Update chunk (len=%u): %@", len, chunk);
    return orig_CC_MD5_Update(c, data, len);
}

// ---------- Hook CC_MD5_Final（流式最终结果） ----------
static int hooked_CC_MD5_Final(unsigned char *md, CC_MD5_CTX *c) {
    int ret = orig_CC_MD5_Final(md, c);
    NSMutableString *hex = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", md[i]];
    NSLog(@"[MD5-HOOK] Final  Digest: %@", hex);
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
}