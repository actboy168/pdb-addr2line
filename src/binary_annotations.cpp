#include "binary_annotations.h"

bool ReadCompressedAnnotation(const std::uint8_t*& current, const std::uint8_t* end, std::uint32_t& value) {
    if (current >= end) {
        return false;
    }

    const std::uint8_t first = *current++;
    if ((first & 0x80u) == 0u) {
        value = first;
        return true;
    }

    if (current >= end) {
        return false;
    }

    const std::uint8_t second = *current++;
    if ((first & 0xC0u) == 0x80u) {
        value = ((first & 0x3Fu) << 8) | second;
        return true;
    }

    if (current + 1 >= end) {
        return false;
    }

    const std::uint8_t third = *current++;
    const std::uint8_t fourth = *current++;
    if ((first & 0xC0u) == 0xC0u) {
        value =
            ((first & 0x3Fu) << 24) |
            (static_cast<std::uint32_t>(second) << 16) |
            (static_cast<std::uint32_t>(third) << 8) |
            fourth;
        return true;
    }

    return false;
}

int DecodeSignedAnnotation(std::uint32_t operand) {
    return (operand & 1u) ? -static_cast<int>(operand >> 1) : static_cast<int>(operand >> 1);
}

bool ReadDecodedAnnotation(const std::uint8_t*& current, const std::uint8_t* end, DecodedAnnotation& annotation) {
    std::uint32_t opcode_value = 0;
    if (!ReadCompressedAnnotation(current, end, opcode_value)) {
        return false;
    }

    annotation = {};
    annotation.op = static_cast<BinaryAnnotationOpCode>(opcode_value);

    switch (annotation.op) {
    case BinaryAnnotationOpCode::Invalid:
        return true;

    case BinaryAnnotationOpCode::CodeOffset:
    case BinaryAnnotationOpCode::ChangeCodeOffsetBase:
    case BinaryAnnotationOpCode::ChangeCodeOffset:
    case BinaryAnnotationOpCode::ChangeCodeLength:
    case BinaryAnnotationOpCode::ChangeFile:
    case BinaryAnnotationOpCode::ChangeLineEndDelta:
    case BinaryAnnotationOpCode::ChangeRangeKind:
    case BinaryAnnotationOpCode::ChangeColumnStart:
    case BinaryAnnotationOpCode::ChangeColumnEnd:
        return ReadCompressedAnnotation(current, end, annotation.u1);

    case BinaryAnnotationOpCode::ChangeLineOffset:
    case BinaryAnnotationOpCode::ChangeColumnEndDelta: {
        std::uint32_t operand = 0;
        if (!ReadCompressedAnnotation(current, end, operand)) {
            return false;
        }
        annotation.s1 = DecodeSignedAnnotation(operand);
        return true;
    }

    case BinaryAnnotationOpCode::ChangeCodeOffsetAndLineOffset: {
        std::uint32_t operand = 0;
        if (!ReadCompressedAnnotation(current, end, operand)) {
            return false;
        }
        annotation.s1 = DecodeSignedAnnotation(operand >> 4);
        annotation.u1 = operand & 0xFu;
        return true;
    }

    case BinaryAnnotationOpCode::ChangeCodeLengthAndCodeOffset:
        return ReadCompressedAnnotation(current, end, annotation.u1) &&
            ReadCompressedAnnotation(current, end, annotation.u2);
    }

    return false;
}
