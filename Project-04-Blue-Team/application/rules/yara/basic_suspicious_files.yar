rule Executable_Header_In_Text_File {
  strings:
    $mz = { 4D 5A }
    $elf = { 7F 45 4C 46 }
  condition:
    uint16(0) == 0x5A4D or uint32(0) == 0x464C457F
}

rule Suspicious_Powershell_EncodedCommand {
  strings:
    $a = "powershell -enc" nocase
    $b = "powershell -encodedcommand" nocase
  condition:
    any of them
}
