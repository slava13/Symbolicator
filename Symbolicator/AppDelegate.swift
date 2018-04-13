//
//  AppDelegate.swift
//  Symbolicator
//
//  Created by Yaroslav Kopylov on 2/19/18.
//  Copyright © 2018 com.macpawlabs.symbolicator All rights reserved.
//

import Cocoa

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {
    
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}
