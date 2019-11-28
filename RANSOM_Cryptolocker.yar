import "pe"

rule CryptoLocker_set1
{

meta:

	author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
	date = "2014-04-13"
	description = "Detection of Cryptolocker Samples"
	
strings:

	$string0 = "static"
	$string1 = " kscdS"
	$string2 = "Romantic"
	$string3 = "CompanyName" wide
	$string4 = "ProductVersion" wide
	$string5 = "9%9R9f9q9"
	$string6 = "IDR_VERSION1" wide
	$string7 = "  </trustInfo>"
	$string8 = "LookFor" wide
	$string9 = ":n;t;y;"
	$string10 = "        <requestedExecutionLevel level"
	$string11 = "VS_VERSION_INFO" wide
	$string12 = "2.0.1.0" wide
	$string13 = "<assembly xmlns"
	$string14 = "  <trustInfo xmlns"
	$string15 = "srtWd@@"
	$string16 = "515]5z5"
	$string17 = "C:\\lZbvnoVe.exe" wide

condition:

	12 of ($string*)
}

rule CryptoLocker_rule2
{

meta:

	author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
	date = "2014-04-14"
	description = "Detection of CryptoLocker Variants"

strings:

	$string0 = "2.0.1.7" wide
	$string1 = "    <security>"
	$string2 = "Romantic"
	$string3 = "ProductVersion" wide
	$string4 = "9%9R9f9q9"
	$string5 = "IDR_VERSION1" wide
	$string6 = "button"
	$string7 = "    </security>"
	$string8 = "VFileInfo" wide
	$string9 = "LookFor" wide
	$string10 = "      </requestedPrivileges>"
	$string11 = " uiAccess"
	$string12 = "  <trustInfo xmlns"
	$string13 = "last.inf"
	$string14 = " manifestVersion"
	$string15 = "FFFF04E3" wide
	$string16 = "3,31363H3P3m3u3z3"

condition:

	12 of ($string*)
}


