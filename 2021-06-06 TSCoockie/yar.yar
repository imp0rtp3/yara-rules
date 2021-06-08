
rule apt_CN_blacktech_TSCookie_freebds {
	strings:

	$comm_code_1 = {04 BC 63 72 }
	$comm_code_2 = {03 BC 63 72 }
	$comm_code_3 = {02 BC 63 72 }
	$comm_code_4 = {09 BC 63 72 }
	$comm_code_5 = {08 BC 63 72 }
	$comm_code_6 = {0B BC 63 72 }
	$comm_code_7 = {07 BC 63 72 }
	$comm_code_8 = {06 BC 63 72 }
	$comm_code_9 = {0A BC 63 72 }
	$comm_code_10 = {05 BC 63 72 }
	$comm_code_11 = {01 AC 00 72}
	$comm_code_12 = {02 AC 00 72}
	$comm_code_13 = {07 AC 00 72}
	$comm_code_14 = {1F 00 65 9A }
	$comm_code_15 = {69 D0 EC F4 FF FF}
	$comm_code_16 = {1D F3 01 00}
	$comm_code_17 = {A7 41 00 00}

	$a1 = "/usr/bin/host %s" fullword
	$a2 = "id;pwd\n" fullword
	$a3 = {25 73 25 73 00 61 62 2B 00 72 62 00}
	$b1 = "mv %s %s" fullword
	$b2 = "rm -rf %s" fullword
	$b3 = "has address " fullword
	$b4 = "exit\n" fullword
	$c1 = "/dev/null" fullword
	$c2 = "127.0.0.1" fullword
	$c3 = "/bin/sh" fullword
	$d1 = "220.135.71.92@443"


condition:
	9 of ($comm_code*) or
	$d or 
	all of ($a*) or 
	(4 of ($comm_code*) and any of ($a*)) or
	(any of ($a*) and all of ($b*)) or 
	(2 of ($a*) and all of ($c*)) or
	(all of ($c*) and all of ($b*))


}