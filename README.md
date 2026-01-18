# Hexrays Signed

Highlights signed comparisons in the Pseudocode-View of IDA Pro's Hexrays decompiler.

## Usage

The plugin automatically highlights signed comparison operations in the decompiled pseudocode:
- **Red highlight**: Unsigned comparisons
- **Error color**: 16-bit signed comparisons
- Other: Standard signed operations

Supported operations:
- `>=` (signed greater-or-equal)
- `<=` (signed less-or-equal)
- `>` (signed greater-than)
- `<` (signed less-than)
- `/` (signed division)
- `%` (signed modulo)

## Requirements

- IDA Pro 9.0 or later
- Hexrays decompiler

## License

MIT
