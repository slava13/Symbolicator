//
//  ViewController.swift
//  Symbolicator
//
//  Created by Yaroslav Kopylov on 2/19/18.
//  Copyright © 2018 com.macpawlabs.symbolicator All rights reserved.
//

import Foundation
import Cocoa

class ViewController: NSViewController {
    
    private struct Symbolicator {
        let pathExtension: String
        let processor: Processor
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        dropReport.onDragFiles = { urls in
            self.urlsForSample = urls
        }
        dropDSYM.onDragFiles = { urls in
            self.urlsForDSYM = urls
        }
    }
    
    @IBOutlet weak var showResult: NSTextField!
    @IBOutlet weak var showSpinner: NSProgressIndicator!
    
    
    @IBOutlet weak var dropReport: DragAndDropView! {
        didSet {
            dropReport.dialogTitle = ""
            dropReport.expectedExtensions = ["txt", "crash"]
        }
    }
    
    @IBOutlet weak var dropDSYM: DragAndDropView! {
        didSet {
            dropDSYM.dialogTitle = ""
            dropDSYM.expectedExtensions = ["dSYM"]
        }
    }

    private(set) var urlsForSample: [URL]?
    private(set) var urlsForDSYM: [URL]?
    private let fileManager = FileManager.default
    
    private lazy var tasks: [Symbolicator] = {
        return [
            Symbolicator(pathExtension: "txt", processor: Sample()),
            Symbolicator(pathExtension: "crash", processor: CrashSymbolicate())
        ]
    }()
    
    private func startSymbolicateProcess(task: Symbolicator) {
        //      let checker = Dwarfdump()
        guard let nonOptionalSampleU = urlsForSample else { return }
        guard let nonOptionalDsymURL = urlsForDSYM else { return }
        
        showSpinner.startAnimation(self)
        task.processor.process(reportUrl: nonOptionalSampleU[0], dsymUrl: nonOptionalDsymURL) { (output, error) in
            if let output = output {
                self.showSpinner.stopAnimation(self)
                self.showResult.stringValue = "File saved!"
                self.showResult.sizeToFit()
                NSWorkspace.shared.openFile(output.output)
            } else if let error = error {
                self.showSpinner.stopAnimation(self)
                let nsAlert = NSAlert()
                nsAlert.informativeText = error.text
                nsAlert.addButton(withTitle: "Got it!")
                nsAlert.beginSheetModal(for: self.view.window!, completionHandler: { (modalResponse) -> Void in
                    if modalResponse == NSApplication.ModalResponse.alertFirstButtonReturn {
                        return
                    }
                })
            }
            self.showSpinner.stopAnimation(self)
        }
    }
    
    @IBAction func symbThisFile(_ sender: Any) {
        self.showResult.stringValue = ""
        guard
            let urlForSample = urlsForSample,
            let _ = urlsForDSYM else {
                self.showResult.stringValue = "Please add files"
                self.showResult.sizeToFit()
                return
            }
        
        let fileExtension = urlForSample[0].pathExtension
        guard let task = tasks.first(where: { $0.pathExtension == fileExtension })
            else { return }
        startSymbolicateProcess(task: task)
    }
    
    @IBAction func restPaths(_ sender: Any) {
        urlsForSample = nil
        urlsForDSYM = nil
        showSpinner.stopAnimation(self)
        showResult.stringValue = ""
        dropDSYM.resetDsym()
        dropReport.resetReport()
    }
}

private extension ProcessorError {
    var text: String {
        switch self {
        case .empty(let text):
            return text
        case .badInput:
            return "Something went wrong"
        default:
            return "Something went wrong"
        }
    }
}
