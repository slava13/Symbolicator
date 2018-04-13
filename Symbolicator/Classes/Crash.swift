//
//  Crash.swift
//  Symbolicator
//
//  Created by Yaroslav Kopylov on 2/27/18.
//  Copyright © 2018 com.macpawlabs.symbolicator All rights reserved.
//

import Foundation
import Cocoa

enum ProcessorError: Error {
    case empty(String)
    case badInput
    case success
}

protocol Processor {
    
    func process(reportUrl: URL, dsymUrl: URL,  completion: @escaping (ReportOutput?, ProcessorError?) -> Void)
}

class CrashSymbolicate: Processor {
    
    let fileManager = FileManager.default
    var stringForAtos = ""
    let symbQueue = DispatchQueue.global(qos: .userInitiated)
    let checkForUUID = Dwarfdump()

    func process(reportUrl: URL, dsymUrl: URL, completion: @escaping (ReportOutput?, ProcessorError?) -> Void) {
        symbQueue.async {
            
            let resultSubDir = self.fileManager.subpaths(atPath: dsymUrl.path)
            guard self.fileManager.fileExists(atPath: dsymUrl.appendingPathComponent("/Contents/Resources/DWARF").path) else {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.badInput)
                }
                return
            }
            self.stringForAtos = dsymUrl.appendingPathComponent(resultSubDir![3]).path.removingPercentEncoding!
            var pureLoadAddress = ""
            let file = self.readFile(at: reportUrl)
            let appName = self.findNameOfTheProcess(for: file)
            let bundleID = self.findBundleID(for: file)
            var loadAddress = self.findLoaddedAddress(for: file, bundleID: bundleID)
            let uuid = self.findUUID(for: file, bundleID: bundleID)
            let functionAddresses = self.findAddressesValues(for: file, appName: appName, bundleID: bundleID)
            let outputOfDwarfdump = self.checkForUUID.checkUUID(launchPath: "/usr/bin/dwarfdump", arguments: ["--uuid", "\(self.stringForAtos)"])

            // not emp
            if file.isEmpty {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.empty("File is empty"))
                }
                return
            } else if loadAddress.isEmpty {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.empty("LoadAddress is empty"))
                }
                return
            } else if bundleID.isEmpty {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.empty("BundleID is empty"))
                }
                return
            } else if uuid.isEmpty {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.empty("UUID is empty"))
                }
                return
            } else if  appName.isEmpty {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.empty("ApplicationName is empty"))
                }
                return
            } else if functionAddresses.isEmpty {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.empty("FunctionAddresses are empty"))
                }
                return
            } else if !outputOfDwarfdump.contains("\(uuid)") {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.empty("Please find appropriate dSYM with:\n \(uuid)"))
                }
                return
            }
            
            var arguments: [String] = {
                if loadAddress.isEmpty == true {
                    return [""]
                } else {
                    pureLoadAddress = loadAddress.filter({$0 != ""})[0]
                    var args = ["-o", self.stringForAtos, "-l", pureLoadAddress]
                    args.append(contentsOf: functionAddresses.filter({$0 != ""}))
                    return args
                }
            }()
            
            let output = self.simbolicate(launchPath: "/usr/bin/atos", arguments: arguments)
            var arrayOfOutput: [String] {
                var arrayOutput = output.components(separatedBy: "\n")
                arrayOutput.removeLast()
                return arrayOutput }
            
            if arrayOfOutput.isEmpty {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.empty("Output is empty"))
                }
                return
            }
            
            let match = self.matchOutput(for: file, arrayOfOutput: arrayOfOutput, pureLoadAddress: pureLoadAddress, appName: appName)
            let finalFulltext = match
            do {
                let outputFilePath = try self.writeToFile(at: reportUrl, fulltext: finalFulltext)
                let result = ReportOutput(output: outputFilePath, uuid: uuid)
                DispatchQueue.main.async {
                    completion(result, nil)
                }
            } catch {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.badInput)
                }
            }
        }
    }
    
    
    private(set) var error = ""
    
    private func readFile(at url: URL) -> [String] {
        var myStrings: [String] = []
        do {
            // Read the file contents
            let readString = try String(contentsOf: url)
            myStrings = readString.components(separatedBy: .newlines)
        } catch let error as NSError {
            print("Failed reading from URL: \(url), Error: " + error.localizedDescription)
        }
        return myStrings
    }
    
    private func findBundleID(for file: [String]) -> String {
        var nameOfTheProcess = ""
        for line in file {
            let findTheProcess = line.range(of: "^Identifier:.*", options:.regularExpression)
            if findTheProcess != nil {
                nameOfTheProcess = line.replacingOccurrences(of: "Identifier:", with: "").trimmingCharacters(in: .whitespaces)
                break // so it wouldn't parse Parent Process which is: ???
            }
        }
        return nameOfTheProcess
    }
    
    private func findNameOfTheProcess(for file: [String]) -> String {
        var processName = ""
        for line in file {
            let findProcessName = line.range(of: "^Process:.*", options:.regularExpression)
            if findProcessName != nil {
                let nameOfTheProcess = line.replacingOccurrences(of: "Process:", with: "")
                processName = nameOfTheProcess.replacingOccurrences(of: "\\[.*", with: "", options: .regularExpression).trimmingCharacters(in: .whitespaces)
                break // so it wouldn't parse Parent Process which is: ???
            }
        }
        return processName
    }
    
    private func findUUID(for file: [String], bundleID: String ) -> String {
        var uuidForCrash = ""
        for line in file {
            let lookForUUID = line.range(of: "[+]\(bundleID)", options:.regularExpression)
            if lookForUUID != nil {
                let nsString = line as NSString
                let regex = try! NSRegularExpression(pattern: "<.*>", options: [])
                let lookRegex = regex.matches(in: line, options: [], range: NSMakeRange(0, nsString.length))
                let value = lookRegex.map { nsString.substring(with: $0.range)}
                let noParent = String(describing: value).replacingOccurrences(of: "[\"<", with: "")
                uuidForCrash = String(noParent).replacingOccurrences(of: ">\"]", with: "")
                break
            }
        }
        return uuidForCrash
    }
    
    private func findLoaddedAddress(for file: [String], bundleID: String) -> [String] {
        var pureLoaddedAdress: [String] = []
        for line in file {
            let lookForLoad = line.range(of: "\(bundleID)[ ]", options:.regularExpression)
            if lookForLoad != nil {
                let nsString = line as NSString
                let regex = try! NSRegularExpression(pattern: "0x10.*", options: [])
                let lookRegex = regex.matches(in: line, options: [], range: NSMakeRange(0, nsString.length))
                let value = lookRegex.map { nsString.substring(with: $0.range)}
                let noParent = String(describing: value).replacingOccurrences(of: "[\\[\\]^]", with: "", options: .regularExpression).prefix(12)
                pureLoaddedAdress.append(noParent.replacingOccurrences(of: "\"", with: ""))
            }
        }
        return pureLoaddedAdress
    }
    
    private func findAddressesValues(for file: [String], appName: String, bundleID: String) -> [String] {
        var pureAddressesValues: [String] = []
        for lines in file {
            let lookForAddresses = lines.range(of: "\(appName)[ ][+]", options:.regularExpression)
            let lookForAddresses2 = lines.range(of: "\(bundleID)[ ]", options:.regularExpression)
            if lookForAddresses != nil || lookForAddresses2 != nil {
                let nsString = lines as NSString
                let regex = try! NSRegularExpression(pattern: "0x00.*", options: [])
                let lookRegex = regex.matches(in: lines, options: [], range: NSMakeRange(0, nsString.length))
                let value = lookRegex.map { nsString.substring(with: $0.range)}
                let noParent = String(describing: value).replacingOccurrences(of: "[\\[\\]^]", with: "", options: .regularExpression).prefix(19)
                pureAddressesValues.append(noParent.replacingOccurrences(of: "\"", with: ""))
            }
        }
        return pureAddressesValues
    }
    
    private func simbolicate(launchPath: String, arguments: [String]) -> String {
        let taskForAtos = Process()
        taskForAtos.launchPath = launchPath
        taskForAtos.arguments = arguments
        
        let pipe = Pipe()
        taskForAtos.standardOutput = pipe
        taskForAtos.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output: String = NSString(data: data, encoding: String.Encoding.utf8.rawValue)! as String
        
        return output
    }
    
    private func matchOutput(for file: [String], arrayOfOutput: [String], pureLoadAddress: String, appName: String) -> String {
        var counter = 0
        var mutableText: [String] = file
        
        for line in mutableText {
            let lookFor = line.range(of: "0x00.*[ ]\(pureLoadAddress)[ ]", options:.regularExpression)
            let lookFor2 = line.range(of: "0x00.*[ ]\(appName)[ ][+]", options:.regularExpression)
            if lookFor2 != nil {
                if let index = mutableText.index(of: line) {
                    mutableText[index] = line.replacingOccurrences(of: "\(appName) +", with: "\(arrayOfOutput[counter])")
                }
                counter += 1
            } else if lookFor != nil {
                    if let index = mutableText.index(of: line) {
                        mutableText[index] = line.replacingOccurrences(of: "\(pureLoadAddress)", with: "\(arrayOfOutput[counter])")
                }
                counter += 1
            }
        }
        let fulltext: String = mutableText.joined(separator: "\n")
        return fulltext
    }
    
    private func writeToFile(at url: URL, fulltext: String) throws -> String {
        let fileToSave = "\(url.deletingPathExtension().lastPathComponent)_Symbolicated-File.txt"
        let dir : NSString = NSSearchPathForDirectoriesInDomains(.desktopDirectory, .allDomainsMask, true).first! as NSString
        let pathToWriteCrash = dir.appendingPathComponent(fileToSave)
        try fulltext.write(toFile: pathToWriteCrash, atomically: false, encoding: String.Encoding.utf8)
        return pathToWriteCrash
    }
}

