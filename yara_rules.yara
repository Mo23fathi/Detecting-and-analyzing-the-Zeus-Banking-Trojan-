rule ZeusBankingVersion_26Nov2013 {   
      
   	strings:   
      
   	   
    		 $a1= "DungBadebankBangGelthoboCocaBozotsksWheyVaryShoghoseNipsCadisi" fullword ascii   
   		 $a2= "SlabKitsSlayseptPfftjiffSabsdeskOafsNowtMemsKirnKepiMiffDunt" fullword ascii   
      
   		 $hex1= {2461313d202244756e}   
   		 $hex2= {2461323d2022536c61}   
      
   	condition:   
   		1 of them   
   }
