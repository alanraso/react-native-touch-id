#import "TouchID.h"
#import <React/RCTUtils.h>
#import "React/RCTConvert.h"
#import <LocalAuthentication/LocalAuthentication.h>

@implementation TouchID

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(authenticate: (NSString *)reason
                  options:(NSDictionary *)options
                  callback: (RCTResponseSenderBlock)callback)
{
    LAContext *context = [[LAContext alloc] init];
    NSError *error;

    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:reason
                          reply:^(BOOL success, NSError *error)
         {
             [self handleAttemptToUseDeviceIDWithSuccess:success error:error callback:callback];
         }];
    } else {
        callback(@[RCTMakeError(@"RCTTouchIDNotSupported", nil, nil)]);
    }
}

- (void)handleAttemptToUseDeviceIDWithSuccess:(BOOL)success error:(NSError *)error callback:(RCTResponseSenderBlock)callback {
    if (success) {
        callback(@[[NSNull null], @"Authenticated with Touch ID."]);
    } else if (error) {
        NSString *errorReason;
        
        switch (error.code) {
            case LAErrorUserCancel:
                errorReason = @"LAErrorUserCancel";
                break;
                
            case LAErrorUserFallback:
                errorReason = @"LAErrorUserFallback";
                break;
                
            case LAErrorSystemCancel:
                errorReason = @"LAErrorSystemCancel";
                break;
                
            case LAErrorPasscodeNotSet:
                errorReason = @"LAErrorPasscodeNotSet";
                break;
                
            case LAErrorTouchIDNotAvailable:
                errorReason = @"LAErrorTouchIDNotAvailable";
                break;
                
            case LAErrorTouchIDNotEnrolled:
                errorReason = @"LAErrorTouchIDNotEnrolled";
                break;
                
            default:
                errorReason = @"LAErrorAuthenticationFailed";
                break;
        }
        
        NSLog(@"Authentication failed: %@", errorReason);
        callback(@[RCTMakeError(errorReason, nil, nil)]);
    }
}

@end
