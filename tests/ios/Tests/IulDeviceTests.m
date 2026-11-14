#import <XCTest/XCTest.h>
#include "untar.h"

extern int run_sbm_api_suite(const char *rootfs_path);
extern int ios_boot_rootfs(const char *rootfs_path);
extern int ios_run_guest_cmd(const char *cmd, char *out, size_t out_size, int timeout_ms);
extern void ios_cleanup_devfs(void);

@interface IulDeviceTests : XCTestCase
@end

@implementation IulDeviceTests

- (void)testSbmApiSuiteOnDevice {
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSString *tgzPath = [bundle pathForResource:@"rootfs" ofType:@"tar.gz"];
    XCTAssertNotNil(tgzPath, @"rootfs.tar.gz must be bundled in test resources");

    NSString *rootfsDir = [NSTemporaryDirectory() stringByAppendingPathComponent:
                           [NSString stringWithFormat:@"iul-rootfs-%@", [[NSUUID UUID] UUIDString]]];
    NSError *err = nil;
    BOOL ok = [[NSFileManager defaultManager] createDirectoryAtPath:rootfsDir
                                       withIntermediateDirectories:YES
                                                        attributes:nil
                                                             error:&err];
    XCTAssertTrue(ok, @"failed to create rootfs dir: %@", err);

    int untarRc = untar_gz([tgzPath fileSystemRepresentation], [rootfsDir fileSystemRepresentation]);
    XCTAssertEqual(untarRc, 0, @"untar_gz failed");

    int rc = run_sbm_api_suite([rootfsDir fileSystemRepresentation]);

    [[NSFileManager defaultManager] removeItemAtPath:rootfsDir error:nil];
    XCTAssertEqual(rc, 0, @"sbm_api_test suite failed with status %d", rc);
}

- (void)runUbuntuCase:(NSString *)name
               marker:(NSString *)marker
               script:(NSString *)script
            rootfsDir:(NSString *)rootfsDir
            timeoutMs:(int)timeoutMs
             failures:(NSMutableArray<NSString *> *)failures {
    NSString *wrapped = [NSString stringWithFormat:
        @"(set -e; %@) >/tmp/case.log 2>&1; rc=$?; "
        @"if [ $rc -ne 0 ]; then echo \"CASE_RC=$rc\"; tail -n 40 /tmp/case.log; "
        @"else tail -n 20 /tmp/case.log; echo \"CASE_RC=0\"; fi",
        script];
    char out[65536];
    memset(out, 0, sizeof(out));
    NSDate *start = [NSDate date];
    int rc = ios_run_guest_cmd([wrapped UTF8String], out, sizeof(out), timeoutMs);
    NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:start];
    NSString *output = [NSString stringWithUTF8String:out] ?: @"";
    BOOL ok = (rc == 0) && [output containsString:@"CASE_RC=0"] && [output containsString:marker];
    NSLog(@"[ubuntu/%@] %@ (%.1fs, rc=%d)", name, ok ? @"PASS" : @"FAIL", elapsed, rc);
    if (!ok) {
        if (output.length == 0) {
            NSString *caseLog = [NSString stringWithContentsOfFile:
                [rootfsDir stringByAppendingPathComponent:@"tmp/case.log"]
                encoding:NSUTF8StringEncoding error:nil];
            if (caseLog.length > 2000)
                caseLog = [caseLog substringFromIndex:caseLog.length - 2000];
            output = caseLog ?: @"(no case.log)";
        }
        NSLog(@"[ubuntu/%@ output]\n%@", name, output);
        [failures addObject:[NSString stringWithFormat:@"ubuntu/%@ (rc=%d)", name, rc]];
    }
}

- (void)testUbuntuFullOnDevice {
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSString *tgzPath = [bundle pathForResource:@"rootfs" ofType:@"tar.gz"];
    XCTAssertNotNil(tgzPath, @"rootfs.tar.gz must be bundled in test resources");

    NSString *rootfsDir = [NSTemporaryDirectory() stringByAppendingPathComponent:
                           [NSString stringWithFormat:@"iul-ubuntu-%@", [[NSUUID UUID] UUIDString]]];
    NSError *err = nil;
    BOOL ok = [[NSFileManager defaultManager] createDirectoryAtPath:rootfsDir
                                       withIntermediateDirectories:YES
                                                        attributes:nil
                                                             error:&err];
    XCTAssertTrue(ok, @"failed to create rootfs dir: %@", err);

    int untarRc = untar_gz([tgzPath fileSystemRepresentation], [rootfsDir fileSystemRepresentation]);
    XCTAssertEqual(untarRc, 0, @"untar_gz failed");

    NSString *etcDir = [rootfsDir stringByAppendingPathComponent:@"etc"];
    [[NSFileManager defaultManager] createDirectoryAtPath:etcDir withIntermediateDirectories:YES attributes:nil error:nil];
    [@"127.0.0.1\tlocalhost\n::1\t\tlocalhost ip6-localhost ip6-loopback\n"
        writeToFile:[etcDir stringByAppendingPathComponent:@"hosts"]
         atomically:YES
           encoding:NSUTF8StringEncoding
              error:nil];
    [@"nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
        writeToFile:[etcDir stringByAppendingPathComponent:@"resolv.conf"]
         atomically:YES
           encoding:NSUTF8StringEncoding
              error:nil];

    int bootRc = ios_boot_rootfs([rootfsDir fileSystemRepresentation]);
    XCTAssertEqual(bootRc, 0, @"ios_boot_rootfs failed: %d", bootRc);

    NSMutableArray<NSString *> *failures = [NSMutableArray array];

    [self runUbuntuCase:@"apt-update"
                 marker:@"APT-UPDATE-OK"
                 script:@"DEBIAN_FRONTEND=noninteractive apt-get update -qq && echo APT-UPDATE-OK"
              rootfsDir:rootfsDir
              timeoutMs:300000
               failures:failures];

    [self runUbuntuCase:@"sqlite"
                 marker:@"SQLITE-OK 40"
                 script:@"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sqlite3 && "
                        @"apt-get clean && "
                        @"DB=/tmp/usq.db; "
                        @"sqlite3 $DB 'PRAGMA journal_mode=WAL; CREATE TABLE t(v int);' >/dev/null && "
                        @"sqlite3 $DB 'INSERT INTO t VALUES (1),(2),(3);' && "
                        @"n=$(sqlite3 $DB 'SELECT count(*) FROM t;'); "
                        @"echo \"SQLITE-OK $(($n * 10 + 10))\""
              rootfsDir:rootfsDir
              timeoutMs:180000
               failures:failures];

    [self runUbuntuCase:@"git"
                 marker:@"GIT-OK 0 1"
                 script:@"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends git >/dev/null && "
                        @"apt-get clean && "
                        @"git config --global --add safe.directory '*' && "
                        @"mkdir -p /tmp/ug/src && cd /tmp/ug/src && "
                        @"git config --global user.name t && git config --global user.email t@t && "
                        @"git init -q && echo hi > f && git add f && git commit -q -m init && "
                        @"git clone -q /tmp/ug/src /tmp/ug/dst && "
                        @"git -C /tmp/ug/dst fsck --strict >/dev/null && "
                        @"echo \"GIT-OK $? $(grep -c hi /tmp/ug/dst/f)\""
              rootfsDir:rootfsDir
              timeoutMs:360000
               failures:failures];

    [self runUbuntuCase:@"redis"
                 marker:@"REDIS-OK ok"
                 script:@"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends redis-server redis-tools && "
                        @"apt-get clean && "
                        @"mkdir -p /tmp/urd; "
                        @"redis-server --port 6399 --save '' --appendonly no --dir /tmp/urd --daemonize no & "
                        @"i=0; while [ $i -lt 100 ]; do redis-cli -p 6399 ping 2>/dev/null | grep -q PONG && break; i=$((i+1)); sleep 0.2; done; "
                        @"redis-cli -p 6399 ping && "
                        @"if command -v redis-benchmark >/dev/null 2>&1; then redis-benchmark -p 6399 -n 1000 -c 5 -t set,get -q >/dev/null; else redis-cli -p 6399 set k v >/dev/null && redis-cli -p 6399 get k; fi && "
                        @"redis-cli -p 6399 bgsave >/dev/null && sleep 2 && "
                        @"s=$(redis-cli -p 6399 info persistence | tr -d '\\r' | sed -n 's/^rdb_last_bgsave_status://p'); "
                        @"redis-cli -p 6399 shutdown nosave 2>/dev/null || true; "
                        @"echo REDIS-OK $s"
              rootfsDir:rootfsDir
              timeoutMs:360000
               failures:failures];

    [self runUbuntuCase:@"node"
                 marker:@"NODE-OK 42"
                 script:@"echo NODE-INSTALL-START && "
                        @"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nodejs && "
                        @"echo NODE-INSTALL-DONE && "
                        @"apt-get clean && "
                        @"timeout 20 node -e 'console.log(\"NODE-OK\", 40 + 2)'"
              rootfsDir:rootfsDir
              timeoutMs:360000
               failures:failures];

    [self runUbuntuCase:@"cc"
                 marker:@"CC-OK 42"
                 script:@"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends gcc libc6-dev && "
                        @"apt-get clean && "
                        @"mkdir -p /tmp/uc && cd /tmp/uc && "
                        @"printf '#include <stdio.h>\\nint main(void){printf(\"CC-OK %%d\\\\n\",40+2);return 0;}\\n' > h.c && "
                        @"cc -O2 h.c -o h && ./h"
              rootfsDir:rootfsDir
              timeoutMs:600000
               failures:failures];

    ios_cleanup_devfs();
    [[NSFileManager defaultManager] removeItemAtPath:rootfsDir error:nil];
    XCTAssertEqual(failures.count, 0, @"Failed Ubuntu suites: %@", failures);
}

- (void)testUbuntuDpkgQuick {
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSString *tgzPath = [bundle pathForResource:@"rootfs" ofType:@"tar.gz"];
    XCTAssertNotNil(tgzPath);

    NSString *rootfsDir = [NSTemporaryDirectory() stringByAppendingPathComponent:
                           [NSString stringWithFormat:@"iul-ubuntu-q-%@", [[NSUUID UUID] UUIDString]]];
    [[NSFileManager defaultManager] createDirectoryAtPath:rootfsDir withIntermediateDirectories:YES attributes:nil error:nil];
    XCTAssertEqual(untar_gz([tgzPath fileSystemRepresentation], [rootfsDir fileSystemRepresentation]), 0);

    NSString *etcDir = [rootfsDir stringByAppendingPathComponent:@"etc"];
    [[NSFileManager defaultManager] createDirectoryAtPath:etcDir withIntermediateDirectories:YES attributes:nil error:nil];
    [@"127.0.0.1\tlocalhost\n::1\t\tlocalhost ip6-localhost ip6-loopback\n"
        writeToFile:[etcDir stringByAppendingPathComponent:@"hosts"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [@"nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
        writeToFile:[etcDir stringByAppendingPathComponent:@"resolv.conf"] atomically:YES encoding:NSUTF8StringEncoding error:nil];

    XCTAssertEqual(ios_boot_rootfs([rootfsDir fileSystemRepresentation]), 0);

    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    [self runUbuntuCase:@"sqlite-quick"
                 marker:@"SQLITE-OK 40"
                 script:@"DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
                        @"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sqlite3 && "
                        @"sqlite3 --version && echo 'SQLITE-OK 40'"
              rootfsDir:rootfsDir
              timeoutMs:180000
               failures:failures];

    ios_cleanup_devfs();
    [[NSFileManager defaultManager] removeItemAtPath:rootfsDir error:nil];
    XCTAssertEqual(failures.count, 0, @"Failed: %@", failures);
}

@end
