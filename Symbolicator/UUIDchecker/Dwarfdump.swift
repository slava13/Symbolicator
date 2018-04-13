//
//  Dwarfdump.swift
//  Symbolicator
//
//  Created by Yaroslav Kopylov on 3/16/18.
//  Copyright © 2018 com.abtester.script. All rights reserved.
//

import Cocoa
import Foundation


class Dwarfdump {

    public func checkUUID(launchPath: String, arguments: [String]) -> String {
        let task = Process()
        task.launchPath = launchPath
        task.arguments = arguments

        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output: String = NSString(data: data, encoding: String.Encoding.utf8.rawValue)! as String

        return output
    }
}


