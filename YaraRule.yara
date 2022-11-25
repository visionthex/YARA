rule Yara_Example {

	meta: 
		last_updated = "2022-11-24"
		author = "PMAT"
		description = "A sample Yara Rule for PMAT"

	strings:
		// Fill out identifying strings and other criteria
		$string1 = "YOURETHEMANNOWDOG" ascii
		$string2 = "nim"
		$PE_magic_byte = "MZ"
		$sus_hex_string = { FF E4 ?? 00 FF }
	
	condition:
		// Fill out the conditions that must be met to identify the binary
		$PE_magic_byte at 0 and
		($string1 and $string2) or

		$sus_hex_string
}
