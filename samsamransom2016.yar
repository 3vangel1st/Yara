
import "pe"

rule SAmSAmRansom2016 {
   meta:
      author = "Christiaan Beek"
      date = "2018-01-25"
      hash1 = "45e00fe90c8aa8578fce2b305840e368d62578c77e352974da6b8f8bc895d75b"
      hash2 = "946dd4c4f3c78e7e4819a712c7fd6497722a3d616d33e3306a556a9dc99656f4"
      hash3 = "979692a34201f9fc1e1c44654dc8074a82000946deedfdf6b8985827da992868"
      hash4 = "939efdc272e8636fd63c1b58c2eec94cf10299cd2de30c329bd5378b6bbbd1c8"
      hash5 = "a763ed678a52f77a7b75d55010124a8fccf1628eb4f7a815c6d635034227177e"
      hash6 = "e682ac6b874e0a6cfc5ff88798315b2cb822d165a7e6f72a5eb74e6da451e155"
      hash7 = "6bc2aa391b8ef260e79b99409e44011874630c2631e4487e82b76e5cb0a49307"
      hash8 = "036071786d7db553e2415ec2e71f3967baf51bdc31d0a640aa4afb87d3ce3050"
      hash9 = "ffef0f1c2df157e9c2ee65a12d5b7b0f1301c4da22e7e7f3eac6b03c6487a626"
      hash10 = "89b4abb78970cd524dd887053d5bcd982534558efdf25c83f96e13b56b4ee805"
      hash11 = "7aa585e6fd0a895c295c4bea2ddb071eed1e5775f437602b577a54eef7f61044"
      hash12 = "0f2c5c39494f15b7ee637ad5b6b5d00a3e2f407b4f27d140cd5a821ff08acfac"
      hash13 = "58ef87523184d5df3ed1568397cea65b3f44df06c73eadeb5d90faebe4390e3e"
   strings:
      $x1 = "Could not list processes locking resource. Failed to get size of result." fullword wide
      $s2 = "Could not list processes locking resource." fullword wide
      $s3 = "samsam.del.exe" fullword ascii
      $s4 = "samsam.exe" fullword wide
      $s5 = "RM_UNIQUE_PROCESS" fullword ascii
      $s6 = "KillProcessWithWait" fullword ascii
      $s7 = "killOpenedProcessTree" fullword ascii
      $s8 = "RM_PROCESS_INFO" fullword ascii
      $s9 = "Exception caught in process: {0}" fullword wide
      $s10 = "Could not begin restart session.  Unable to determine file locker." fullword wide
      $s11 = "samsam.Properties.Resources.resources" fullword ascii
      $s12 = "EncryptStringToBytes" fullword ascii
      $s13 = "recursivegetfiles" fullword ascii
      $s14 = "RSAEncryptBytes" fullword ascii
      $s15 = "encryptFile" fullword ascii
      $s16 = "samsam.Properties.Resources" fullword wide
      $s17 = "TSSessionId" fullword ascii
      $s18 = "Could not register resource." fullword wide
      $s19 = "<recursivegetfiles>b__0" fullword ascii
      $s20 = "create_from_resource" fullword ascii

      $op0 = { 96 00 e0 00 29 00 0b 00 34 23 }
      $op1 = { 96 00 12 04 f9 00 34 00 6c 2c }
      $op2 = { 72 a5 0a 00 70 a2 06 20 94 }
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 700KB and
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them ) and all of ($op*)
      ) or ( all of them )
}

