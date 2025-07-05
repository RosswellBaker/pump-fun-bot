from typing import List, Optional, Tuple
import base64
import struct

# Configurable threshold for the creator's initial buy amount
CREATOR_INITIAL_BUY_THRESHOLD = 50000000  # 50 million tokens
BUY_DISCRIMINATOR = 16927863322537952870  # Global constant for "buy" instruction
TOKEN_DECIMALS = 6  # Pump.fun uses 6 decimals

def get_buy_instruction_amount(logs: List[str]) -> Optional[float]:
    """
    NUCLEAR DEBUG - Shows EVERYTHING about Program data entries
    """
    print(f"\n{'='*80}")
    print(f"ANALYZING TRANSACTION LOGS ({len(logs)} total lines)")
    print(f"{'='*80}")
    
    # First, map out the entire transaction structure
    instruction_map = {}
    program_data_map = {}
    current_instruction = None
    
    for i, log in enumerate(logs):
        # Track instructions
        if "Program log: Instruction:" in log:
            instruction_name = log.split("Instruction: ")[1].strip()
            current_instruction = instruction_name
            instruction_map[i] = instruction_name
            print(f"Line {i}: Found instruction '{instruction_name}'")
        
        # Track Program data
        if "Program data:" in log:
            program_data_map[i] = {
                'after_instruction': current_instruction,
                'log': log
            }
    
    print(f"\nFound {len(instruction_map)} instructions: {list(instruction_map.values())}")
    print(f"Found {len(program_data_map)} Program data entries")
    
    # Now analyze each Program data entry
    for line_num, data_info in program_data_map.items():
        print(f"\n{'='*60}")
        print(f"Program data at line {line_num} (after '{data_info['after_instruction']}' instruction)")
        print(f"{'='*60}")
        
        log = data_info['log']
        
        try:
            # Extract base64 data
            if "Program data: " in log:
                data_start = log.find("Program data: ") + 14
                encoded_data = log[data_start:].strip()
            else:
                print("ERROR: Couldn't find 'Program data: ' prefix")
                continue
            
            print(f"Base64 string (first 50 chars): {encoded_data[:50]}...")
            print(f"Base64 length: {len(encoded_data)}")
            
            # Decode
            decoded_data = base64.b64decode(encoded_data)
            print(f"Decoded length: {len(decoded_data)} bytes")
            print(f"Hex (first 32 bytes): {decoded_data[:32].hex()}")
            
            if len(decoded_data) >= 8:
                # Get discriminator
                discriminator = struct.unpack("<Q", decoded_data[:8])[0]
                print(f"Discriminator (u64): {discriminator}")
                print(f"Discriminator (hex): {decoded_data[:8].hex()}")
                
                # Check if it matches our expected discriminators
                if discriminator == BUY_DISCRIMINATOR:
                    print("*** MATCHES BUY_DISCRIMINATOR! ***")
                elif discriminator == 8530921459188068891:
                    print("*** This is CREATE discriminator ***")
                else:
                    print(f"Unknown discriminator")
                
                # If it could be a buy instruction, try to parse it
                if len(decoded_data) >= 24:
                    # Try to parse as buy instruction regardless of discriminator
                    test_amount = struct.unpack("<Q", decoded_data[8:16])[0]
                    test_max_sol = struct.unpack("<Q", decoded_data[16:24])[0]
                    
                    print(f"\nIF this were a buy instruction:")
                    print(f"  Amount (raw): {test_amount}")
                    print(f"  Amount (tokens): {test_amount / (10 ** TOKEN_DECIMALS):,.6f}")
                    print(f"  Max SOL (raw): {test_max_sol}")
                    print(f"  Max SOL (SOL): {test_max_sol / 1e9:.6f}")
                    
                    # Does this look reasonable?
                    if 0 < test_amount / (10 ** TOKEN_DECIMALS) <= 1_000_000_000:
                        print(f"  ^ This amount looks reasonable for tokens!")
                        
                        if discriminator == BUY_DISCRIMINATOR:
                            print(f"  AND discriminator matches! Returning {test_amount / (10 ** TOKEN_DECIMALS):,.6f}")
                            return test_amount / (10 ** TOKEN_DECIMALS)
                        else:
                            print(f"  BUT discriminator doesn't match BUY_DISCRIMINATOR")
                            print(f"  Maybe BUY_DISCRIMINATOR is wrong?")
                
        except Exception as e:
            print(f"ERROR parsing: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*80}")
    print("END OF ANALYSIS - No matching buy instruction found")
    print(f"{'='*80}")
    return None


def should_process_token(logs: List[str], signature: str) -> Tuple[bool, Optional[float]]:
    """
    Nuclear debug version
    """
    print(f"\n{'#'*80}")
    print(f"SHOULD_PROCESS_TOKEN: {signature}")
    print(f"{'#'*80}")
    
    is_create = any("Program log: Instruction: Create" in log for log in logs)
    
    if not is_create:
        print("Not a Create transaction - PASS THROUGH")
        return True, None
    
    print("This IS a Create transaction - checking buy amount...")
    
    buy_amount = get_buy_instruction_amount(logs)
    
    if buy_amount is None:
        print("RESULT: No buy amount found - REJECT")
        return False, None
    
    should_process = buy_amount <= CREATOR_INITIAL_BUY_THRESHOLD
    print(f"\nRESULT: Buy amount {buy_amount:,.6f} vs threshold {CREATOR_INITIAL_BUY_THRESHOLD:,} = {'PASS' if should_process else 'REJECT'}")
    
    return should_process, buy_amount