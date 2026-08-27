#!/usr/bin/env swift
import AppKit
import Foundation

// Generate a Finder DMG window background:
// take the top-left quarter of the app icon, draw it semi-transparent into the
// bottom-right quarter of the canvas, and leave the rest clean.

func fail(_ message: String) -> Never {
    fputs("error: \(message)\n", stderr)
    exit(1)
}

let args = CommandLine.arguments
guard args.count >= 3 else {
    fail("usage: generate-macos-dmg-background.swift <icon.png> <output.png> [width] [height] [opacity]")
}

let iconPath = args[1]
let outputPath = args[2]
let canvasWidth = args.count > 3 ? (Int(args[3]) ?? 660) : 660
let canvasHeight = args.count > 4 ? (Int(args[4]) ?? 420) : 420
let opacity = args.count > 5 ? (CGFloat(Double(args[5]) ?? 0.18)) : 0.18

guard let icon = NSImage(contentsOfFile: iconPath) else {
    fail("failed to load icon: \(iconPath)")
}

let iconSize = icon.size
guard iconSize.width > 0, iconSize.height > 0 else {
    fail("icon has empty size: \(iconPath)")
}

let canvas = NSImage(size: NSSize(width: canvasWidth, height: canvasHeight))
canvas.lockFocus()

// Clean off-white background that reads well in light Finder themes.
NSColor(calibratedWhite: 0.96, alpha: 1.0).setFill()
NSBezierPath(rect: NSRect(x: 0, y: 0, width: canvasWidth, height: canvasHeight)).fill()

// Crop the icon's top-left quarter in source image space.
// NSImage draws with bottom-left origin; map crop accordingly.
let cropWidth = iconSize.width / 2.0
let cropHeight = iconSize.height / 2.0
// Top-left quarter of the icon:
// source origin.y is measured from bottom, so top half starts at height/2.
let sourceRect = NSRect(
    x: 0,
    y: iconSize.height / 2.0,
    width: cropWidth,
    height: cropHeight
)

// Destination: bottom-right quarter of the DMG window canvas.
let destRect = NSRect(
    x: CGFloat(canvasWidth) / 2.0,
    y: 0,
    width: CGFloat(canvasWidth) / 2.0,
    height: CGFloat(canvasHeight) / 2.0
)

// Fit the crop into the destination while preserving aspect ratio, then pin
// it toward the lower-right corner for a watermark feel.
let scale = min(destRect.width / sourceRect.width, destRect.height / sourceRect.height)
let drawWidth = sourceRect.width * scale
let drawHeight = sourceRect.height * scale
let drawRect = NSRect(
    x: destRect.maxX - drawWidth - destRect.width * 0.08,
    y: destRect.minY + destRect.height * 0.08,
    width: drawWidth,
    height: drawHeight
)

icon.draw(
    in: drawRect,
    from: sourceRect,
    operation: .sourceOver,
    fraction: max(0.05, min(opacity, 1.0)),
    respectFlipped: true,
    hints: [
        .interpolation: NSImageInterpolation.high
    ]
)

canvas.unlockFocus()

guard let tiff = canvas.tiffRepresentation,
      let rep = NSBitmapImageRep(data: tiff),
      let png = rep.representation(using: .png, properties: [:]) else {
    fail("failed to encode background PNG")
}

do {
    try png.write(to: URL(fileURLWithPath: outputPath))
} catch {
    fail("failed to write \(outputPath): \(error)")
}

print(outputPath)
