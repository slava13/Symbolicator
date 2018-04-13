//
//  NSImage+QuickLook.h
//  QuickLookTest
//
//  Created by Matt Gemmell on 29/10/2007.
//

#ifndef NSImage_QuickLook_h
#define NSImage_QuickLook_h


#endif /* NSImage_QuickLook_h */

#import <Cocoa/Cocoa.h>


@interface NSImage (QuickLook)

+ (NSImage *)imageWithPreviewOfFileAtPath:(NSString *)path ofSize:(NSSize)size asIcon:(BOOL)icon;

@end
