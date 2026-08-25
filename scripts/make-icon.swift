import AppKit
import Foundation
import ImageIO

// Renders the application icon (1024×1024 master PNG) with Core Graphics so the
// artwork stays reproducible from source instead of living as a binary blob.

let canvas: CGFloat = 1024

func color(_ hex: UInt32, alpha: CGFloat = 1) -> NSColor {
    NSColor(
        srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
        green: CGFloat((hex >> 8) & 0xFF) / 255,
        blue: CGFloat(hex & 0xFF) / 255,
        alpha: alpha
    )
}

func squirclePath(in rect: NSRect, radius: CGFloat) -> NSBezierPath {
    // Approximates Apple's continuous corner curve with a high-order bezier.
    let path = NSBezierPath()
    let k: CGFloat = 0.42
    let minX = rect.minX, maxX = rect.maxX, minY = rect.minY, maxY = rect.maxY
    path.move(to: NSPoint(x: minX + radius, y: minY))
    path.line(to: NSPoint(x: maxX - radius, y: minY))
    path.curve(
        to: NSPoint(x: maxX, y: minY + radius),
        controlPoint1: NSPoint(x: maxX - radius * k, y: minY),
        controlPoint2: NSPoint(x: maxX, y: minY + radius * k)
    )
    path.line(to: NSPoint(x: maxX, y: maxY - radius))
    path.curve(
        to: NSPoint(x: maxX - radius, y: maxY),
        controlPoint1: NSPoint(x: maxX, y: maxY - radius * k),
        controlPoint2: NSPoint(x: maxX - radius * k, y: maxY)
    )
    path.line(to: NSPoint(x: minX + radius, y: maxY))
    path.curve(
        to: NSPoint(x: minX, y: maxY - radius),
        controlPoint1: NSPoint(x: minX + radius * k, y: maxY),
        controlPoint2: NSPoint(x: minX, y: maxY - radius * k)
    )
    path.line(to: NSPoint(x: minX, y: minY + radius))
    path.curve(
        to: NSPoint(x: minX + radius, y: minY),
        controlPoint1: NSPoint(x: minX, y: minY + radius * k),
        controlPoint2: NSPoint(x: minX + radius * k, y: minY)
    )
    path.close()
    return path
}

func cloudPath() -> NSBezierPath {
    let path = NSBezierPath()
    path.windingRule = .nonZero
    path.append(
        NSBezierPath(
            roundedRect: NSRect(x: 300, y: 470, width: 424, height: 122),
            xRadius: 61,
            yRadius: 61
        )
    )
    path.appendOval(in: NSRect(x: 306, y: 482, width: 180, height: 180))
    path.appendOval(in: NSRect(x: 388, y: 492, width: 248, height: 248))
    path.appendOval(in: NSRect(x: 556, y: 478, width: 166, height: 166))
    return path
}

let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: Int(canvas),
    pixelsHigh: Int(canvas),
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0,
    bitsPerPixel: 0
)!
rep.size = NSSize(width: canvas, height: canvas)

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)!
let context = NSGraphicsContext.current!.cgContext

let body = NSRect(x: 92, y: 92, width: 840, height: 840)
let bodyPath = squirclePath(in: body, radius: 196)

// Drop shadow so the icon reads as a physical tile on light desktops.
context.saveGState()
context.setShadow(offset: CGSize(width: 0, height: -10), blur: 52, color: color(0x0B1533, alpha: 0.18).cgColor)
color(0x2E5BE6).setFill()
bodyPath.fill()
context.restoreGState()

// Base gradient.
context.saveGState()
bodyPath.addClip()
NSGradient(colorsAndLocations:
    (color(0x74A8FF), 0.0),
    (color(0x3D6BF0), 0.42),
    (color(0x1B2A8C), 0.78),
    (color(0x101A4F), 1.0)
)!.draw(in: body, angle: -70)

// Soft top-left sheen.
NSGradient(colorsAndLocations:
    (color(0xFFFFFF, alpha: 0.34), 0.0),
    (color(0xFFFFFF, alpha: 0.0), 1.0)
)!.draw(
    fromCenter: NSPoint(x: 300, y: 900),
    radius: 0,
    toCenter: NSPoint(x: 300, y: 900),
    radius: 620,
    options: []
)

// Faint orbit rings hint at continuous synchronisation.
color(0xFFFFFF, alpha: 0.10).setStroke()
for radius in [300.0, 400.0, 500.0] as [CGFloat] {
    let ring = NSBezierPath(
        ovalIn: NSRect(x: 512 - radius, y: 540 - radius, width: radius * 2, height: radius * 2)
    )
    ring.lineWidth = 6
    ring.stroke()
}
context.restoreGState()

// Inner rim light.
context.saveGState()
let rim = squirclePath(in: body.insetBy(dx: 5, dy: 5), radius: 191)
rim.lineWidth = 6
color(0xFFFFFF, alpha: 0.22).setStroke()
rim.stroke()
context.restoreGState()

let badgeCenter = NSPoint(x: 726, y: 358)
let badgeRadius: CGFloat = 128

// Cloud, with a clean cut-out where the sync badge sits on top of it.
context.saveGState()
bodyPath.addClip()
let cutout = NSBezierPath()
cutout.windingRule = .evenOdd
cutout.append(NSBezierPath(rect: NSRect(x: 0, y: 0, width: canvas, height: canvas)))
cutout.appendOval(
    in: NSRect(
        x: badgeCenter.x - badgeRadius - 26,
        y: badgeCenter.y - badgeRadius - 26,
        width: (badgeRadius + 26) * 2,
        height: (badgeRadius + 26) * 2
    )
)
cutout.addClip()

let cloud = cloudPath()
context.saveGState()
context.setShadow(offset: CGSize(width: 0, height: -10), blur: 30, color: color(0x081234, alpha: 0.45).cgColor)
NSColor.white.setFill()
cloud.fill()
context.restoreGState()

cloud.addClip()
NSGradient(colorsAndLocations:
    (color(0xFFFFFF), 0.0),
    (color(0xDCE9FF), 1.0)
)!.draw(in: NSRect(x: 300, y: 470, width: 424, height: 270), angle: -90)
context.restoreGState()

// Sync badge.
context.saveGState()
let badge = NSBezierPath(
    ovalIn: NSRect(
        x: badgeCenter.x - badgeRadius,
        y: badgeCenter.y - badgeRadius,
        width: badgeRadius * 2,
        height: badgeRadius * 2
    )
)
context.setShadow(offset: CGSize(width: 0, height: -8), blur: 24, color: color(0x3A1400, alpha: 0.45).cgColor)
color(0xF6821F).setFill()
badge.fill()
context.restoreGState()

context.saveGState()
badge.addClip()
NSGradient(colorsAndLocations:
    (color(0xFFB854), 0.0),
    (color(0xF6821F), 0.55),
    (color(0xE0620A), 1.0)
)!.draw(
    in: NSRect(
        x: badgeCenter.x - badgeRadius,
        y: badgeCenter.y - badgeRadius,
        width: badgeRadius * 2,
        height: badgeRadius * 2
    ),
    angle: -90
)
context.restoreGState()

// Circular refresh arrow inside the badge.
let arrowRadius: CGFloat = 58
let startAngle: CGFloat = 108
let endAngle: CGFloat = -118
let arc = NSBezierPath()
arc.appendArc(
    withCenter: badgeCenter,
    radius: arrowRadius,
    startAngle: startAngle,
    endAngle: endAngle,
    clockwise: true
)
arc.lineWidth = 25
arc.lineCapStyle = .round
NSColor.white.setStroke()
arc.stroke()

let radians = endAngle * .pi / 180
let anchor = NSPoint(
    x: badgeCenter.x + cos(radians) * arrowRadius,
    y: badgeCenter.y + sin(radians) * arrowRadius
)
let tangent = NSPoint(x: sin(radians), y: -cos(radians))
let normal = NSPoint(x: cos(radians), y: sin(radians))
let head = NSBezierPath()
head.move(to: NSPoint(x: anchor.x + tangent.x * 50, y: anchor.y + tangent.y * 50))
head.line(to: NSPoint(x: anchor.x + normal.x * 40 - tangent.x * 10, y: anchor.y + normal.y * 40 - tangent.y * 10))
head.line(to: NSPoint(x: anchor.x - normal.x * 40 - tangent.x * 10, y: anchor.y - normal.y * 40 - tangent.y * 10))
head.close()
NSColor.white.setFill()
head.fill()

NSGraphicsContext.restoreGraphicsState()

let outputPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon-1024.png"
let outputURL = URL(fileURLWithPath: outputPath)

if outputURL.pathExtension.lowercased() == "icns" {
    guard let image = rep.cgImage,
          let destination = CGImageDestinationCreateWithURL(
              outputURL as CFURL, "com.apple.icns" as CFString, 6, nil
          ) else {
        FileHandle.standardError.write(Data("无法创建 ICNS 输出\n".utf8))
        exit(1)
    }

    for size in [16, 32, 128, 256, 512, 1024] {
        guard let context = CGContext(
            data: nil,
            width: size,
            height: size,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: CGColorSpace(name: CGColorSpace.sRGB)!,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else {
            FileHandle.standardError.write(Data("无法创建图标缩放上下文\n".utf8))
            exit(1)
        }
        context.interpolationQuality = .high
        context.draw(image, in: CGRect(x: 0, y: 0, width: size, height: size))
        guard let resized = context.makeImage() else {
            FileHandle.standardError.write(Data("无法生成图标尺寸\n".utf8))
            exit(1)
        }
        CGImageDestinationAddImage(destination, resized, nil)
    }

    guard CGImageDestinationFinalize(destination) else {
        FileHandle.standardError.write(Data("无法写入 ICNS 输出\n".utf8))
        exit(1)
    }
    print("已生成 \(outputPath)")
    exit(0)
}

guard let data = rep.representation(using: .png, properties: [:]) else {
    FileHandle.standardError.write(Data("无法编码 PNG\n".utf8))
    exit(1)
}
try data.write(to: outputURL)
print("已生成 \(outputPath)")
