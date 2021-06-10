import "pe"
import "dotnet"

rule apt_RU_gamaredon_sboska
{
	meta:
		author      = "imp0rtp3"
		description = "Sborka malware by Gamaredon"
		reference   = "https://twitter.com/JAMESWT_MHT/status/1402589421459984387"
		sha256      = "31afda4abdc26d379b848d214c8cbd0b7dc4d62a062723511a98953bebe8cbfc"

	strings:
		$a1 = "Rambox_0_7_7_win_x64" wide fullword
		$a2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide fullword
		$a3 = "schtasks.exe /Create /sc minute /mo " wide fullword
		$a4 = "USERDOMAIN_ROAMINGPROFILE" wide fullword
		$a5 = "/TN \"" wide fullword
		$a6 = "PROCESSOR_IDENTIFIER" wide fullword
		$a7 = "\" /TR \"" wide fullword
		$a8 = ".exe \" /F" wide fullword
		$a9 = "VolumeSerialNumber" wide fullword
		$a10 = "logicaldisk.DeviceID" wide fullword
		$a11 = "='C:'" wide fullword
		
		// Strings in the PDB or related to the internal name
		$b1 = "t00Sborka"
		$b2 = "mchta.pdb"
		$b3 = "Y:\\Projects\\T04\\"
		$b5 = "\\alldelete\\obj\\Release\\"
		$b6 = { d0 a0 d1 83 d1 87 d0 bd d0 b0 d1 8f 20 d1 81 d0 b1 d0 be d1 80 d0 ba d0 b0 }
		$b7 = "mchta.Properties.Resources" wide fullword

		// Opcodes Apeearing many times for obfuscation purposes. Here apparently querying registry.
		$opcodes_1 = { 72 [4] 13 ?? 7E 3B 00 00 ?? 11 ?? 6F ?? 00 00 ?? 13 ?? 11 ?? 6F ?? 00 00 ?? 13 0? 16 13 0? 2B ?? 11 0? 11 0? 9A 13 ?? 11 ?? 11 ?? 6F ?? 00 00 ?? 13 ?? 11 ?? 72 [2] 00 ?? 6F ?? 00 00 ?? 28 ?? 00 00 ?? DE }

		// Here apparently querying WMI.
		$opcodes_2 = {72 [4] 73 ?? 00 00 ?? 13 ?? 11 ?? 6F ?? 00 00 ?? 13 ?? 73 ?? 00 00 ?? 26 11 ?? 6F ?? 00 00 ?? 13 ?? 2B ?? 11 ?? 6F ?? 00 00 0A 74 ?? 00 00 01 72 [2] 00 70 6F ?? 00 00 0A 74 ?? 00 00 ?? 26 11 ?? 6F ?? 00 00 0A 2D ?? DE }
		
	condition:
		uint16(0) == 0x5A4D and (
			9 of ($a*) or
			3 of ($b*) or 
			(
				6 of ($a*) and
				any of ($b*)
			) or
			pe.version_info["Comments"] == "mceuxmocqvw" or
			(
				pe.version_info["ProductVersion"] == "41.1.3.425" and 
				any of ($b*)
			) or 
			(
				(
					dotnet.assembly.name == "mchta" or pe.version_info["InternalName"] == "mchta.exe"
				) and
				3 of ($a*)
			) or
			(
				(
					(
						dotnet.number_of_resources == 0 and filesize < 500000 
					) or
					(
						filesize - (dotnet.resources[0].length) < 500000
					)
				) and
				#opcodes_1 >30 and 
				#opcodes_2 > 30 
			)	
		)
}