//
//  Advanced.swift
//  Symbolicator
//
//  Created by Yaroslav2 Kopylov2 on 12/1/18.
//  Copyright © 2018 com.macpawlabs.symbolicator All rights reserved.
//

import Foundation
import Cocoa

struct ReportOutput {
    var output: String
}

class Sample: Processor {
    
    private struct Task {
        
        let dsymPath: String
        let loadAddress: String
        let addressesValues: [String]
    }
    
    let fileManager = FileManager.default
    let symbQueue = DispatchQueue.global(qos: .userInitiated)
    let checkForUUID = Dwarfdump()
    
    func process(reportUrl: URL, dsymUrl: [URL], completion: @escaping (ReportOutput?, ProcessorError?) -> Void) {
        let file = self.readFile(at: reportUrl)
        let bundleID = self.findBundleID(for: file)
        let assosiatedFrameworks = self.getAssosiatedFrameworks(for: file, with: bundleID)
        let appName = self.findTheNameOfTheApp(for: file)
        let filteredAssosiatedFrameworks = assosiatedFrameworks.filter { $0 != "" }
        symbQueue.async {
            var tasks: [Task] = []
            let existingDsyms = dsymUrl.filter({ (url) -> Bool in
                return self.fileManager.fileExists(atPath: url.appendingPathComponent("/Contents/Resources/DWARF").path)
            })
            
            guard existingDsyms.isNotEmpty else {
                DispatchQueue.main.async {
                    completion(nil, ProcessorError.badInput)
                }
                return
            }
            
            for url in dsymUrl {
                let resultSubDir = self.fileManager.subpaths(atPath: url.path)
                let stringForAtos = url.appendingPathComponent(resultSubDir![3]).path.removingPercentEncoding!
                var dictLoadAddressesForFramework = [String : String]()
                var dictOfAddressesValues = [String : [String]]()
                
                var addressesAndValues:[(framework: String, loadedAddress:String, valuesAddresses:[String] )] = filteredAssosiatedFrameworks
                    .map { framework in
                        return (framework: framework,
                                loadedAddress: self.findLoaddedAddress(for: file, frameworkName: framework, bundleID: bundleID),
                                valuesAddresses: self.findAddressesValues(for: file, frameworkName: framework)
                        )
                    }
                    .filter { $0.valuesAddresses.isNotEmpty
                }
                //needed to get load address and addresses values for App itself (not only frameworks)
                let valuesAddressesForApp = self.findAddressesValues(for: file, frameworkName: appName)
                if valuesAddressesForApp.isNotEmpty {
                    addressesAndValues.append((framework: appName,
                                               loadedAddress: self.findLoaddedAddressForApp(for: file, bundleID: bundleID),
                                               valuesAddresses: self.findAddressesValues(for: file, frameworkName: appName)))
                }
              
                addressesAndValues.forEach {
                    dictLoadAddressesForFramework[$0.framework] = $0.loadedAddress
                    dictOfAddressesValues[$0.framework] = $0.valuesAddresses
                }
                
                let frameworkNames = Array(dictLoadAddressesForFramework.keys.filter { stringForAtos.contains($0.appending("."))})
                for framework in frameworkNames {
                    guard let loadAddress = dictLoadAddressesForFramework[framework] else { return }
                    guard let addressesValues = dictOfAddressesValues[framework] else { return }
                    tasks.append(Task(dsymPath: stringForAtos, loadAddress: loadAddress, addressesValues: addressesValues))
                }
            }

            let finalFulltext = file.joined(separator: "\n")
            let finalText: String = tasks
                .reduce(finalFulltext) { text, task in
                    var arguments: [String] = {
                        var args = ["-o", task.dsymPath, "-l", task.loadAddress]
                        args.append(contentsOf: task.addressesValues)
                        return args
                    }()
                    let output = self.simbolicate(launchPath: "/usr/bin/atos", arguments: arguments)
                    var arrayOfOutput: [String] {
                        var arrayOutput = output.components(separatedBy: "\n")
                        arrayOutput.removeLast()
                        return arrayOutput
                    }
                    let zipped = zip(task.addressesValues, arrayOfOutput)
                    return self.matchOutput(in: text, replacements: zipped)
            }
            do {
                let outputFilePath = try self.writeToFile(at: reportUrl, fulltext: finalText)
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
    
    private func getAssosiatedFrameworks(for file: [String], with bundleID: String) -> [String] {
        var assosiatedFrameworks = [""]
        for line in file {
            let frameworkBundle = line.range(of: "[+]\(bundleID).*", options:.regularExpression)
            if frameworkBundle != nil {
                let nsString = line as NSString
                let regex = try! NSRegularExpression(pattern: "[+]\(bundleID).*[(]", options: [])
                let lookRegex = regex.matches(in: line, options: [], range: NSMakeRange(0, nsString.length))
                let value = lookRegex.map { nsString.substring(with: $0.range)}
                let noParent = String(describing: value).replacingOccurrences(of: "(\"]", with: "").trimmingCharacters(in: .whitespaces)
                let frameworkNameWithBundleID = String(noParent).replacingOccurrences(of: "[\"+", with: "")
                assosiatedFrameworks.append(frameworkNameWithBundleID.replacingOccurrences(of: "\(bundleID).", with: ""))
            }
        }
        return assosiatedFrameworks
    }
    
    private func findLoaddedAddress(for file: [String], frameworkName: String, bundleID: String) -> String {
        var pureLoaddedAdress = ""
        for line in file {
            let lookForLoad = line.range(of: "[+]\(bundleID).\(frameworkName).*", options:.regularExpression)
            if lookForLoad != nil {
                let nsString = line as NSString
                let regex = try! NSRegularExpression(pattern: "0x1.*", options: [])
                let lookRegex = regex.matches(in: line, options: [], range: NSMakeRange(0, nsString.length))
                let value = lookRegex.map { nsString.substring(with: $0.range)}
                let noParent = String(describing: value).replacingOccurrences(of: "[\\[\\]^]", with: "", options: .regularExpression).prefix(12)
                pureLoaddedAdress.append(noParent.replacingOccurrences(of: "\"", with: ""))
            }
        }
        return pureLoaddedAdress
    }
    
    private func findLoaddedAddressForApp(for file: [String], bundleID: String) -> String {
        var pureLoaddedAdress = ""
        for line in file {
            let lookForLoad = line.range(of: "[+]\(bundleID) ", options:.regularExpression)
            if lookForLoad != nil {
                let nsString = line as NSString
                let regex = try! NSRegularExpression(pattern: "0x1.*", options: [])
                let lookRegex = regex.matches(in: line, options: [], range: NSMakeRange(0, nsString.length))
                let value = lookRegex.map { nsString.substring(with: $0.range)}
                let noParent = String(describing: value).replacingOccurrences(of: "[\\[\\]^]", with: "", options: .regularExpression).prefix(12)
                pureLoaddedAdress.append(noParent.replacingOccurrences(of: "\"", with: ""))
            }
        }
        return pureLoaddedAdress
    }
    
    private func findAddressesValues(for file: [String], frameworkName: String) -> [String] {
        var pureAddressesValues: [String] = []
        for lines in file {
            let lookForAddresses = lines.range(of: "in \(frameworkName).*", options:.regularExpression)
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
    
    private func matchOutput(in text: String, replacements: Zip2Sequence<[String], [String]>) -> String {
        var fulltext = text
        for (key, value) in replacements {
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
