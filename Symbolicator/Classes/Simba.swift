//
//  Simba.swift
//  Symbolicator
//
//  Created by Yaroslav Kopylov on 2/19/18.
//  Copyright © 2018 com.macpawlabs.symbolicator All rights reserved.
//

import Foundation
import QuickLook

struct ReportOutput {
    var output: String
  //  var uuid: String
}

// review: rename
class Sample: Processor {
    
//    var stringForAtos = ""
    let fileManager = FileManager.default
    let symbQueue = DispatchQueue.global(qos: .userInitiated)
    let checkForUUID = Dwarfdump()
    
    func process(reportUrl: URL, dsymUrl: [URL], completion: @escaping (ReportOutput?, ProcessorError?) -> Void) {
        symbQueue.async {
            let existingDsyms = dsymUrl.filter({ (url) -> Bool in
                return self.fileManager.fileExists(atPath: url.appendingPathComponent("/Contents/Resources/DWARF").path)
            })
            
            guard existingDsyms.isNotEmpty else {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.badInput)
                }
                return
            }
            
        for url in existingDsyms {
            let resultSubDir = self.fileManager.subpaths(atPath: url.path)
            let stringForAtos = url.appendingPathComponent(resultSubDir![3]).path.removingPercentEncoding!
            let file = self.readFile(at: reportUrl)
            let loadAddress = self.findLoaddedAddress(for: file)
            let bundleID = self.findBundleID(for: file)
            let uuid = self.findUUID(for: file, bundleID: bundleID)
            let appName = self.findTheNameOfTheApp(for: file)
            let functionAddresses = self.findAddressesValues(for: file, appName: appName)
            let outputOfDwarfdump = self.checkForUUID.checkUUID(launchPath: "/usr/bin/dwarfdump", arguments: ["--uuid", "\(stringForAtos)"])
            
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
                var args = ["-o", stringForAtos, "-l", loadAddress]
                args.append(contentsOf: functionAddresses)
                return args
            }()
            let output = self.simbolicate(launchPath: "/usr/bin/atos", arguments: arguments)
            
            var arrayOfOutput: [String] {
                var arrayOutput = output.components(separatedBy: "\n")
                arrayOutput.removeLast()
                return arrayOutput
            }
            
            
            let zipped = zip(functionAddresses, arrayOfOutput)
            let finalFulltext = file.joined(separator: "\n")
            
            let textToWrite = self.matchOutput(at: reportUrl, for: file, zipped: zipped, fulltext: finalFulltext)
            
            do {
                let outputFilePath = try self.writeToFile(at: reportUrl, fulltext: textToWrite)
                let result = ReportOutput(output: outputFilePath)
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
        }
            
        
    
    
    private(set) var pathToWriteSample = ""
    private(set) var error = ""
    public struct MyStruct {
        var uuid: String
    }
    
    public enum MyEnum {
        case empty
        case notEmpty
    }
    
    private func readFile(at url: URL) -> [String] {
        var myStrings: [String] = []
        do {
            let readString = try String(contentsOf: url)
            myStrings = readString.components(separatedBy: .newlines)
        } catch {
            print("Failed reading from URL: \(url), Error: " + error.localizedDescription)
        }
        return myStrings
    }
    
    private func findLoaddedAddress(for file: [String]) -> String {
        var loaddedAddress: String = ""
        for line in file {
            let lookForLoad = line.range(of: "^[L]oad", options: .regularExpression)
            if lookForLoad != nil {
                loaddedAddress = line.replacingOccurrences(of: "Load Address:", with: "").trimmingCharacters(in: .whitespaces)
                break
            }
        }
        return loaddedAddress
    }
    
    private func findTheNameOfTheApp(for file: [String]) -> String {
        var nameOfTheApp = ""
        for line in file {
            let findTheProcess = line.range(of: "Process.*", options: .regularExpression)
            if findTheProcess != nil {
                let nameOfTheProcess = line.replacingOccurrences(of: "Process:", with: "")
                nameOfTheApp = nameOfTheProcess.replacingOccurrences(of: "\\[.*", with: "", options: .regularExpression).trimmingCharacters(in: .whitespaces)
                break // so it wouldn't parse Parent Process which is: ???
            }
        }
        return nameOfTheApp
    }
    
    private func findBundleID(for file: [String]) -> String {
        var bundleID = ""
        for line in file {
            let findBundleID = line.range(of: "^Identifier:.*", options:.regularExpression)
            if findBundleID != nil {
                bundleID = line.replacingOccurrences(of: "Identifier:", with: "").trimmingCharacters(in: .whitespaces)
                break // so it wouldn't parse Parent Process which is: ???
            }
        }
        return bundleID
    }
    
    private func findUUID(for file: [String], bundleID: String) -> String {
        var uuidForSample = ""
        for line in file {
            let lookForUUID = line.range(of: "[+]\(bundleID)", options:.regularExpression)
            if lookForUUID != nil {
                let nsString = line as NSString
                let regex = try! NSRegularExpression(pattern: "<.*>", options: [])
                let lookRegex = regex.matches(in: line, options: [], range: NSMakeRange(0, nsString.length))
                let value = lookRegex.map { nsString.substring(with: $0.range)}
                let noParent = String(describing: value).replacingOccurrences(of: "[\"<", with: "")
                uuidForSample = String(noParent).replacingOccurrences(of: ">\"]", with: "")
                break // so it wouldn't parse rest of the bundles which is unnecessary
            }
        }
        return uuidForSample
    }
    
    private func findAddressesValues(for file: [String], appName: String) -> [String] {
        var pureAddressesValues: [String] = []
        for lines in file {
            let lookForAddresses = lines.range(of: "in \(appName).*", options:.regularExpression)
            if lookForAddresses != nil {
                let nsString = lines as NSString
                let regex = try! NSRegularExpression(pattern: "\\[0x.*]", options: [])
                let lookRegex = regex.matches(in: lines, options: [], range: NSMakeRange(0, nsString.length))
                let value = lookRegex.map { nsString.substring(with: $0.range)}
                let noParent = String(describing: value).replacingOccurrences(of: "[\\[\\]^]", with: "", options: .regularExpression)
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
    
    private func matchOutput(at url: URL,for file: [String], zipped: Zip2Sequence<[String], [String]>, fulltext: String) -> String {
        var fulltext = file.joined(separator: "\n")
        for (key, value) in zipped {
            fulltext = fulltext.replacingOccurrences(of: "\(key)", with: "\(value)")
        }
        return fulltext
    }
    
    private func writeToFile(at url: URL, fulltext: String) throws -> String {
        let fileToSave = "\(url.deletingPathExtension().lastPathComponent)_Symbolicated-File.txt"
        let dir : NSString = NSSearchPathForDirectoriesInDomains(.desktopDirectory, .allDomainsMask, true).first! as NSString
        let pathToWriteSample = dir.appendingPathComponent(fileToSave)
        try fulltext.write(toFile: pathToWriteSample, atomically: false, encoding: String.Encoding.utf8)
        return pathToWriteSample
    }
}
