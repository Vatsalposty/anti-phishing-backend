const fs = require('fs');
const path = require('path');

function createBMP(width, height, color) {
    const rowSize = Math.floor((24 * width + 31) / 32) * 4;
    const pixelArraySize = rowSize * height;
    const fileSize = 54 + pixelArraySize;
    const buffer = Buffer.alloc(fileSize);

    // Bitmap Header
    buffer.write('BM', 0); // Signature
    buffer.writeUInt32LE(fileSize, 2); // File size
    buffer.writeUInt32LE(54, 10); // Offset to pixel data

    // DIB Header
    buffer.writeUInt32LE(40, 14); // Header size
    buffer.writeInt32LE(width, 18); // Width
    buffer.writeInt32LE(height, 22); // Height
    buffer.writeUInt16LE(1, 26); // Planes
    buffer.writeUInt16LE(24, 28); // Bits per pixel
    buffer.writeUInt32LE(0, 30); // Compression (BI_RGB)
    buffer.writeUInt32LE(pixelArraySize, 34); // Image size
    buffer.writeInt32LE(2835, 38); // X pixels per meter
    buffer.writeInt32LE(2835, 42); // Y pixels per meter

    // Pixel Data (BGR format for BMP)
    // color is [R, G, B]
    const b = color[2];
    const g = color[1];
    const r = color[0];

    let offset = 54;
    for (let y = 0; y < height; y++) {
        for (let x = 0; x < width; x++) {
            buffer.writeUInt8(b, offset);
            buffer.writeUInt8(g, offset + 1);
            buffer.writeUInt8(r, offset + 2);
            offset += 3;
        }
        // Padding for 4-byte alignment
        const padding = rowSize - (width * 3);
        offset += padding;
    }

    return buffer;
}

const iconsDir = path.join(__dirname, '../icons');
if (!fs.existsSync(iconsDir)) {
    fs.mkdirSync(iconsDir, { recursive: true });
}

// Blue color #3b82f6 -> RGB(59, 130, 246)
const blueColor = [59, 130, 246];

const sizes = [16, 48, 128];

sizes.forEach(size => {
    const buffer = createBMP(size, size, blueColor);
    const fileName = `icon${size}.bmp`;
    fs.writeFileSync(path.join(iconsDir, fileName), buffer);
    console.log(`Created ${fileName}`);
});
