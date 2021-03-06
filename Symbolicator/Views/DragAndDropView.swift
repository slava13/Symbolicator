//
//  DropReportView.swift
//  Symbolicator
//
//  Created by Yaroslav Kopylov on 3/3/18.
//  Copyright © 2018 com.macpawlabs.symbolicator All rights reserved.
//

import Cocoa
import QuickLook

class DragAndDropView: NSView {
    
    var filePath: [String]?
    var onDragFiles: (([URL]) -> ()) = { _ in }
    var dialogTitle = ""
    var expectedExtensions: [String] = []
    
    @objc public dynamic var isEnabled: Bool = true {
        didSet {
            alphaValue = isEnabled ? 1.0 : 0.5
        }
    }
    
    public var isPressed = false {
        didSet {
            alphaValue = isPressed ? 0.5 : 1.0
        }
    }
    
    @IBOutlet weak var imagePreview: NSImageView!
    @IBOutlet weak var addReportLabel: NSTextField!
    @IBOutlet weak var dropOrSelectLabel: NSTextField!
    @IBOutlet weak var fileNameLabel: NSTextField!
    
    public func resetDsym() {
        self.filePath = nil
        self.imagePreview.isHidden = false
        self.imagePreview.image = #imageLiteral(resourceName: "whitePlus")
        self.addReportLabel.isHidden = false
        self.dropOrSelectLabel.isHidden = false
        self.fileNameLabel.isHidden = true
    }
    
    public func resetReport() {
        self.filePath = nil
        self.layer?.contents = nil
        
        self.layer?.backgroundColor = NSColor.systemGray.withAlphaComponent(0.2).cgColor
        self.layer?.borderColor = NSColor.gray.cgColor
        self.layer?.cornerRadius = 20
        self.layer?.masksToBounds = true
        self.addReportLabel.isHidden = false
        self.dropOrSelectLabel.isHidden = false
        self.fileNameLabel.isHidden = true
        self.imagePreview.isHidden = false
        self.imagePreview.image = #imageLiteral(resourceName: "whitePlus")
    }
    
    private func setLayer() {
        layer?.backgroundColor = NSColor.systemGray.withAlphaComponent(0.2).cgColor
        layer?.borderColor = NSColor.gray.cgColor
    }
    
    private func setImagePreview(at path: String) {
        let getImage = DispatchQueue.global(qos: .userInitiated)
        getImage.async {
            let image = NSImage(previewOfFileAtPath: path, of: NSSize(width: 40, height: 40), asIcon: true)
            DispatchQueue.main.async {
                self.imagePreview.image = image
                self.imagePreview.isHidden = false
            }
        }
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        wantsLayer = true
        setLayer()
        layer?.cornerRadius = 20
        layer?.masksToBounds = true
        registerForDraggedTypes([NSPasteboard.PasteboardType.URL, NSPasteboard.PasteboardType.fileURL])
    }
    
    override func mouseDown(with event: NSEvent) {
        guard isEnabled else { return }
        isPressed = true
        let dialog = NSOpenPanel()
        dialog.title = "Choose a .txt file"
        dialog.showsResizeIndicator = true
        dialog.showsHiddenFiles = false
        dialog.canChooseDirectories = false
        dialog.canCreateDirectories = false
        dialog.allowsMultipleSelection = false
        dialog.allowedFileTypes = expectedExtensions
        
        guard dialog.runModal() == .OK else {
            isPressed = false
            return
        }
        if let fileURL = dialog.url {
            let path = fileURL.path
            onDragFiles([fileURL])
            setImagePreview(at: path)
            if expectedExtensions.contains("txt") || expectedExtensions.contains("crash") {
                imagePreview.isHidden = false
                addReportLabel.isHidden = true
                dropOrSelectLabel.isHidden = true
                fileNameLabel.isHidden = false
                fileNameLabel.stringValue = URL(fileURLWithPath: path).lastPathComponent
                fileNameLabel.lineBreakMode = NSLineBreakMode(rawValue: 4)!
                isPressed = false
                return
            }
            imagePreview.isHidden = false
            addReportLabel.isHidden = true
            dropOrSelectLabel.isHidden = true
            fileNameLabel.isHidden = false
            fileNameLabel.stringValue = URL(fileURLWithPath: path).lastPathComponent
            fileNameLabel.lineBreakMode = NSLineBreakMode(rawValue: 4)!
            isPressed = false
        }
    }
    
    // MARK: - Dragging
    
    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        if checkExtension(sender)  {
               imagePreview.isHidden = true
                addReportLabel.isHidden = true
                dropOrSelectLabel.isHidden = true
                fileNameLabel.isHidden = true
                layer?.backgroundColor = NSColor.systemBlue.withAlphaComponent(0.5).cgColor
                return .copy
        } else if checkExtension(sender) {
            imagePreview.isHidden = true
            dropOrSelectLabel.isHidden = true
            fileNameLabel.isHidden = true
            layer?.backgroundColor = NSColor.systemBlue.withAlphaComponent(0.5).cgColor
            return .copy
        } else {
            return NSDragOperation()
        }
    }

    override func draggingExited(_ sender: NSDraggingInfo?) {
        setLayer()

        if filePath == nil {
            imagePreview.isHidden = false
            addReportLabel.isHidden = false
            dropOrSelectLabel.isHidden = false
            fileNameLabel.isHidden = true
            return
        } else {
            imagePreview.isHidden = false
            addReportLabel.isHidden = true
            dropOrSelectLabel.isHidden = true
            fileNameLabel.isHidden = false
            return
        }
    }
    
    override func prepareForDragOperation(_ sender: NSDraggingInfo) -> Bool {
        return true
    }
    
    override func draggingEnded(_ sender: NSDraggingInfo) {
        guard let filePath = filePath else { return }
        if expectedExtensions.contains("txt") || expectedExtensions.contains("crash") {
            imagePreview.isHidden = true
            addReportLabel.isHidden = true
            dropOrSelectLabel.isHidden = true
            fileNameLabel.isHidden = false
            fileNameLabel.stringValue = URL(fileURLWithPath: filePath[0]).lastPathComponent
            fileNameLabel.lineBreakMode = NSLineBreakMode(rawValue: 4)!
            setImagePreview(at: filePath[0])
            setLayer()
            return
        }
        addReportLabel.isHidden = true
        fileNameLabel.isHidden = false
        fileNameLabel.stringValue = URL(fileURLWithPath: filePath[0]).lastPathComponent
        fileNameLabel.lineBreakMode = NSLineBreakMode(rawValue: 4)!
        setImagePreview(at: filePath[0])
        setLayer()
    }
    
    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        guard let pasteboard = sender.draggingPasteboard.propertyList(forType: NSPasteboard.PasteboardType(rawValue: "NSFilenamesPboardType")) as? NSArray?,
            let paths = pasteboard else { return  false }
        filePath = paths as? [String]
        let urls = (filePath ?? []) .map { URL(fileURLWithPath: $0) }
        onDragFiles(urls)
        return true
    }
}

private extension DragAndDropView {
    // review: rename
    func checkExtension(_ sender: NSDraggingInfo) -> Bool {
        guard let pasteboard = sender.draggingPasteboard.propertyList(forType: NSPasteboard.PasteboardType(rawValue: "NSFilenamesPboardType")) as? NSArray,
            let path = pasteboard[0] as? String
            else { return false }
        
        let reportFileExtension = URL(fileURLWithPath: path).pathExtension
        return expectedExtensions.contains(reportFileExtension)
    }
}
