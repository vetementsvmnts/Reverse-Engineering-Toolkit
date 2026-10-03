"""
Disassembly module using Capstone.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pwn import ELF

def disassemble_function(binary_path: str, function_name: str = "main") -> list[dict]:
    """
    Disassemble a specific function from an ELF binary.

    Returns a list of dicts with keys: address, mnemonic, op_str.
    """
    try:
        elf = ELF(binary_path, checksec=False)
    except Exception as e:
        raise ValueError(f"Failed to parse ELF: {e}")

    if function_name not in elf.symbols:
        raise ValueError(f"Function '{function_name}' not found in symbols.")

    func_addr = elf.symbols[function_name]
    code = elf.read(func_addr, 200)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = []
    for insn in md.disasm(code, func_addr):
        instructions.append({
            "address":  hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str":   insn.op_str,
        })
        if insn.mnemonic == "ret":
            break

    return instructions


def extract_cmp_constants(instructions: list[dict]) -> list[dict]:
    """
    Scan a list of instructions for 'cmp reg, imm' patterns
    and extract the immediate values.
    """
    comparisons = []
    for insn in instructions:
        if insn["mnemonic"] == "cmp":
            parts = insn["op_str"].split(",")
            if len(parts) == 2:
                dest = parts[0].strip()
                src  = parts[1].strip()
                if src.startswith("0x"):
                    try:
                        hex_val = int(src, 16)
                        comparisons.append({
                            "address":  insn["address"],
                            "register": dest,
                            "hex":      src,
                            "decimal":  hex_val,
                        })
                    except ValueError:
                        pass
    return comparisons
