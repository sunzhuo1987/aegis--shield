<?php
	/*
	 * approto 
	 * L7Э�������
	 */ 

class approto{
	var $DB;
	
	//Construtor
	function approto($DB){
		$this->DB = $DB;
	}
	
	
	//
	function test(){
		
	}
	
	//��ά����count | proto
	function getProtoDataSet(&$xdata){
		$sql = "select count(proto), proto from approto group by proto";
		
		$result = $this->DB->Execute($sql);
		$cnt = 0;
		
		if($result)
		{
   			while ($myrow = $result->FetchRow())
   			{
         		$xdata[$cnt][0] = $myrow[1];
         		$xdata[$cnt][1] = $myrow[0]; 
         		++$cnt;
   			}	
		}
		else
			echo "error";

		return $cnt;
	}
}
?>