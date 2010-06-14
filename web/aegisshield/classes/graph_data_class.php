<?php 
	/*
	 * class graph_data
	 * 用于产生general_display.php文件需要的显示数据
	 * DB保存一个与数据库连接的会话，查询数据库得到相应的数据
	 */
?>
<?php 
/*
 * 
 */
class graph_data{
	var $DB;
	
	/*
	 * constructor
	 */
	function graph_data($DB){
		$this->DB = $DB;
	}
	
	function agTest(){
		$data = array(1,2,5,10,1,3);
		
		return $data;
	}
	
	/*
	 * $xdata 保存的数据
	 * $chart_type 图表类型
	 */
	function getTimeDataSet(&$xdata, $chart_type, $time_start, $time_end){
		 
		$isStart = $this->checkTime($time_start);
		$isEnd = $this->checkTime($time_end);
		/*
		 * 获取开始，结束时间戳
		 */
		if($isStart == "1" && $isEnd == "1")
		{
			$sql = "SELECT min(timestamp), max(timestamp) FROM event ".
					"WHERE timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
      		 		"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'";
		}
		else if($isStart == "1")
		{
			$sql = "SELECT min(timestamp), max(timestamp) FROM event ".
			"WHERE timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'";
		}
		else if($isEnd == "1")
		{
			$sql = "SELECT min(timestamp), max(timestamp) FROM event ".
					"WHERE timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'";
		}
		else{
			$sql = "SELECT min(timestamp), max(timestamp) FROM event ";
		}


  		$result = $this->DB->GetRow($sql);
   		$start_time = $result[0];
   		$stop_time = $result[1];
   		
   		/*
   		 * check if the start_time and stop time is NULL
   		 */
   		
   		
   		$year_start  = date("Y", strtotime($start_time));
   		$month_start = date("m", strtotime($start_time));
   		$day_start   = date("d", strtotime($start_time));
   		$hour_start  = date("H", strtotime($start_time));

   		$year_end  = date("Y", strtotime($stop_time));
   		$month_end = date("m", strtotime($stop_time));
   		$day_end   = date("d", strtotime($stop_time));
   		$hour_end  = date("H", strtotime($stop_time));
   		
   		switch($chart_type)
   		{ 
     		case 1:  // hour
     		{ 
        		$hour_start = 0; $hour_end = 23; 
        		break;
     		}
     		case 2:  // day          
     		{ 
       			$hour_start = -1;
       			break; 
     		}
     		case 4:  // month           
     		{ 
        		$day_start = -1;
        		$hour_start = -1;
        		break; 
     		}
     		case 5: //  year
     		{
     			$day_start = -1;
     			$hour_start = -1;
     			$month_start = -1;
     			break;
     		}
  		}

  		$cnt = 0;


  		for ( $i_year = $year_start; $i_year <= $year_end; $i_year++ )
  		{
     		 $sql = "SELECT count(*) FROM event WHERE ".
             	"YEAR(timestamp) = $i_year";

      		if ( $month_start != -1 )
      		{
         		if ($i_year == $year_start)  $month_start2 = $month_start;  else  $month_start2 = 1;
         		if ($i_year == $year_end)    $month_end2 = $month_end;      else  $month_end2 = 12;

         		for ( $i_month = $month_start2; $i_month <= $month_end2; $i_month++ )
         		{
             		$sql = "SELECT count(*) FROM event WHERE ".
                    "YEAR(timestamp) = $i_year"." AND ".
                    "MONTH(timestamp) = $i_month";

             		if ( $day_start != -1 )
             		{
                		if ($i_month == $month_start)  $day_start2 = $day_start;  else  $day_start2 = 1;
                		if ($i_month == $month_end)    $day_end2 = $day_end;      else  $day_end2 = 31;

                		for ( $i_day = $day_start2; $i_day <= $day_end2; $i_day++ )
                		{
                  			if ( checkdate($i_month, $i_day, $i_year) )
                  			{
                    			$sql = "SELECT count(*) FROM event WHERE ".
                           		"YEAR(timestamp) = $i_year" ." AND ".
                           		"MONTH(timestamp) = $i_month" ." AND ".
                           		"DAY(timestamp) = $i_day";

                   
                    			if ( $hour_start != -1 )
                    			{
                       				for ( $i_hour = $hour_start; $i_hour <= $hour_end; $i_hour++ )
                       				{
                           				$sql = "SELECT count(*) FROM event WHERE ".
                                  		"YEAR(timestamp) = $i_year". " AND ".
                                  		"MONTH(timestamp) = $i_month"." AND ".
                                  		"DAY(timestamp) = $i_day"." AND ".
                                  		"HOUR(timestamp) = $i_hour";

                           				$this->StoreAlertNum($sql, $i_month."/".$i_day."/".$i_year." ".
                                               $i_hour.":00:00 - ".$i_hour.":59:59", 
                                               $xdata, $cnt, $min_threshold);
                           				//StoreAlertNum($sql, $i_month."/".$i_day." ".
                           				//                    $i_hour.":00 - ".$i_hour.":59",
                           				//                    $xdata, $cnt, $min_threshold);
                       				}   // end hour
                    			}
                    			else
                        			$this->StoreAlertNum($sql, $i_month."/".$i_day."/".$i_year, 
                                      $xdata, $cnt, $min_threshold);
                  			}
                		}   // end day
             		}
             		else
               			$this->StoreAlertNum($sql, $i_month."/".$i_year, $xdata, $cnt, $min_threshold);
         		}   	// end month
      		}
      		else
        		$this->StoreAlertNum($sql, $i_year, $xdata, $cnt, $min_threshold);
  		}   // end year

  		return $cnt;
		
	}
	
	function getIpDataSet(&$xdata, $chart_type, $time_start, $time_end){
		/*
		 * 
		 */
		$isStart = $this->checkTime($time_start);
		$isEnd = $this->checkTime($time_end);
		
		if($isStart == "1" && $isEnd == "1")
		{
			if ( $chart_type == 6 ) 
      		 $sql = "SELECT DISTINCT ip_src, COUNT(iphdr.cid) ".
      		 	"FROM iphdr, event ".
          		"WHERE iphdr.sid = event.sid ".
      		 	"AND iphdr.cid = event.cid ".
      		 	"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
      		 	"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
      			"AND ip_src is NOT NULL ".
          		"GROUP BY ip_src ORDER BY ip_src";
      		 
   			else if ($chart_type == 7)
      		 $sql = "SELECT DISTINCT ip_dst, COUNT(iphdr.cid) ".
             	"FROM iphdr, event ".
          		"WHERE iphdr.sid = event.sid ".
      		 	"AND iphdr.cid = event.cid ".
      		 	"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
      		 	"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
      			"AND ip_dst is NOT NULL ".
             	"GROUP BY ip_dst ORDER BY ip_dst";
			
			//print($sql);
		}
		else if($isStart == "1")
		{
			if ( $chart_type == 6 ) 
      		 $sql = "SELECT DISTINCT ip_src, COUNT(iphdr.cid) ".
      		 	"FROM iphdr, event ".
          		"WHERE iphdr.sid = event.sid ".
      		 	"AND iphdr.cid = event.cid ".
          		"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
      			"AND ip_src is NOT NULL ".
          		"GROUP BY ip_src ORDER BY ip_src";
      		 
   			else if ($chart_type == 7)
      		 $sql = "SELECT DISTINCT ip_dst, COUNT(iphdr.cid) ".
      		 	"FROM iphdr, event ".
          		"WHERE iphdr.sid = event.sid ".
      		 	"AND iphdr.cid = event.cid ".
          		"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
      			"AND ip_src is NOT NULL ".
             	"GROUP BY ip_dst ORDER BY ip_dst";
			
			//print($sql);
		}
		else if($isEnd == "1")
		{
			if ( $chart_type == 6 ) 
      		 $sql = "SELECT DISTINCT ip_src, COUNT(iphdr.cid) ".
      		 	"FROM iphdr, event ".
          		"WHERE iphdr.sid = event.sid ".
      		 	"AND iphdr.cid = event.cid ".
          		"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
      			"AND ip_src is NOT NULL ".
          		"GROUP BY ip_src ORDER BY ip_src";
      		 
   			else if ($chart_type == 7)
      		 $sql = "SELECT DISTINCT ip_dst, COUNT(iphdr.cid) ".
      		 	"FROM iphdr, event ".
          		"WHERE iphdr.sid = event.sid ".
      		 	"AND iphdr.cid = event.cid ".
          		"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
      			"AND ip_src is NOT NULL ".
             	"GROUP BY ip_dst ORDER BY ip_dst";
			print($sql);
		}
		else
		{
			if ( $chart_type == 6 ) 
      		 $sql = "SELECT DISTINCT ip_src, COUNT(iphdr.cid) ".
             "FROM iphdr "." WHERE ip_src is NOT NULL ".
             "GROUP BY ip_src ORDER BY ip_src";
   			else if ($chart_type == 7)
      		 $sql = "SELECT DISTINCT ip_dst, COUNT(iphdr.cid) ".
             	"FROM iphdr "." WHERE ip_dst is NOT NULL ".
             	"GROUP BY ip_dst ORDER BY ip_dst";
			
			//print($sql);
		}
		

   		$cnt = 0;
		$result = $this->DB->Execute($sql);
			 
		if($result)
		{
   			while ($myrow = $result->FetchRow() )
   			{
      			if ( $myrow[1] >= $min_threshold )
      			{
         			$xdata[$cnt][0] = $this->agLong2IP($myrow[0]); 
         			$xdata[$cnt][1] = $myrow[1]; 
         			++$cnt;
      			}
   			}	
		}
		else
			echo "Error in getIpDataSet";

   		return $cnt;
	}
	
	function getPortDataSet(&$xdata, $chart_type, $time_start, $time_end){
		/*
		 * 如果开始时间和结束时间存在且正确的话
		 * 将针对某一时间段的数据进行
		 */
		
		$isStart = $this->checkTime($time_start);
		$isEnd = $this->checkTime($time_end);

		if($isStart == "1" && $isEnd == "1")
		{
			if ( $chart_type == 8)//UDP dst.
				$sql = "SELECT DISTINCT udp_dport, COUNT(udphdr.cid) ".
				"FROM udphdr, event ".
				"WHERE udphdr.sid = event.sid AND udphdr.cid = event.cid ".
				"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
				"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
				"AND udp_dport is NOT NULL ".
				"GROUP BY udp_dport ORDER BY udp_dport";
			else if($chart_type == 9)//TCP dst.
      	 		$sql = "SELECT DISTINCT tcp_dport, COUNT(tcphdr.cid) ".
				"FROM tcphdr, event ".
      	 		"WHERE tcphdr.sid = event.sid AND tcphdr.cid = event.cid ".
				"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
				"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
      	 		"AND tcp_dport is NOT NULL ".
				"GROUP BY tcp_dport ORDER BY tcp_dport";
   			else if($chart_type == 10)//UDP src.
   				$sql = "SELECT DISTINCT udp_sport, COUNT(udphdr.cid) ".
				"FROM udphdr, event ".
   				"WHERE udphdr.sid = event.sid AND udphdr.cid = event.cid ".
   				"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
				"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
				"AND udp_sport is NOT NULL ".
				"GROUP BY udp_sport ORDER BY udp_sport";
   			else if($chart_type == 11)//TCP src. 
      			$sql = "SELECT DISTINCT tcp_sport, COUNT(tcphdr.cid) ".
				"FROM tcphdr, event ".
      	 		"WHERE tcphdr.sid = event.sid AND tcphdr.cid = event.cid ".
				"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
				"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
				"AND tcp_sport is NOT NULL ".
				"GROUP BY tcp_sport ORDER BY tcp_sport";
			
			//print($sql);
		}
		else if($isStart == "1")
		{
			if ( $chart_type == 8)//UDP dst.
				$sql = "SELECT DISTINCT udp_dport, COUNT(udphdr.cid) ".
				"FROM udphdr, event ".
				"WHERE udphdr.sid = event.sid AND udphdr.cid = event.cid ".
				"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
				"AND udp_dport is NOT NULL ".
				"GROUP BY udp_dport ORDER BY udp_dport";
			else if($chart_type == 9)//TCP dst.
      	 		$sql = "SELECT DISTINCT tcp_dport, COUNT(tcphdr.cid) ".
				"FROM tcphdr, event ".
      	 		"WHERE tcphdr.sid = event.sid AND tcphdr.cid = event.cid ".
				"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
      	 		"AND tcp_dport is NOT NULL ".
				"GROUP BY tcp_dport ORDER BY tcp_dport";
   			else if($chart_type == 10)//UDP src.
   				$sql = "SELECT DISTINCT udp_sport, COUNT(udphdr.cid) ".
				"FROM udphdr, event ".
   				"WHERE udphdr.sid = event.sid AND udphdr.cid = event.cid ".
   				"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
				"AND udp_sport is NOT NULL ".
				"GROUP BY udp_sport ORDER BY udp_sport";
   			else if($chart_type == 11)//TCP src. 
      			$sql = "SELECT DISTINCT tcp_sport, COUNT(tcphdr.cid) ".
				"FROM tcphdr, event ".
      	 		"WHERE tcphdr.sid = event.sid AND tcphdr.cid = event.cid ".
				"AND timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
				"AND tcp_sport is NOT NULL ".
				"GROUP BY tcp_sport ORDER BY tcp_sport";
			
			//print($sql);
		}
		else if($isEnd == "1")
		{
			if ( $chart_type == 8)//UDP dst.
				$sql = "SELECT DISTINCT udp_dport, COUNT(udphdr.cid) ".
				"FROM udphdr, event ".
				"WHERE udphdr.sid = event.sid AND udphdr.cid = event.cid ".
				"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
				"AND udp_dport is NOT NULL ".
				"GROUP BY udp_dport ORDER BY udp_dport";
			else if($chart_type == 9)//TCP dst.
      	 		$sql = "SELECT DISTINCT tcp_dport, COUNT(tcphdr.cid) ".
				"FROM tcphdr, event ".
      	 		"WHERE tcphdr.sid = event.sid AND tcphdr.cid = event.cid ".
				"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
      	 		"AND tcp_dport is NOT NULL ".
				"GROUP BY tcp_dport ORDER BY tcp_dport";
   			else if($chart_type == 10)//UDP src.
   				$sql = "SELECT DISTINCT udp_sport, COUNT(udphdr.cid) ".
				"FROM udphdr, event ".
   				"WHERE udphdr.sid = event.sid AND udphdr.cid = event.cid ".
				"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
				"AND udp_sport is NOT NULL ".
				"GROUP BY udp_sport ORDER BY udp_sport";
   			else if($chart_type == 11)//TCP src. 
      			$sql = "SELECT DISTINCT tcp_sport, COUNT(tcphdr.cid) ".
				"FROM tcphdr, event ".
      	 		"WHERE tcphdr.sid = event.sid AND tcphdr.cid = event.cid ".
				"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
				"AND tcp_sport is NOT NULL ".
				"GROUP BY tcp_sport ORDER BY tcp_sport";
			
			//print($sql);
		}
		else
		{
			if ( $chart_type == 8)//UDP dst.
				$sql = "SELECT DISTINCT udp_dport, COUNT(udphdr.cid) ".
				"FROM udphdr, event ".
				"WHERE udphdr.sid = event.sid AND udphdr.cid = event.cid ".
				"AND udp_dport is NOT NULL ".
				"GROUP BY udp_dport ORDER BY udp_dport";
			else if($chart_type == 9)//TCP dst.
      	 		$sql = "SELECT DISTINCT tcp_dport, COUNT(tcphdr.cid) ".
				"FROM tcphdr, event ".
      	 		"WHERE tcphdr.sid = event.sid AND tcphdr.cid = event.cid ".
      	 		"AND tcp_dport is NOT NULL ".
				"GROUP BY tcp_dport ORDER BY tcp_dport";
   			else if($chart_type == 10)//UDP src.
   				$sql = "SELECT DISTINCT udp_sport, COUNT(udphdr.cid) ".
				"FROM udphdr, event ".
   				"WHERE udphdr.sid = event.sid AND udphdr.cid = event.cid ".
				"AND udp_sport is NOT NULL ".
				"GROUP BY udp_sport ORDER BY udp_sport";
   			else if($chart_type == 11)//TCP src. 
      			$sql = "SELECT DISTINCT tcp_sport, COUNT(tcphdr.cid) ".
				"FROM tcphdr, event ".
      	 		"WHERE tcphdr.sid = event.sid AND tcphdr.cid = event.cid ".
				"AND tcp_sport is NOT NULL ".
				"GROUP BY tcp_sport ORDER BY tcp_sport";
			
			//print($sql);
		}
		
   
   		$cnt = 0;
		$result = $this->DB->Execute($sql);
			 
		if($result)
		{
   			while ($myrow = $result->FetchRow() )
   			{
      			if ( $myrow[1] >= $min_threshold )
      			{
         			$xdata[$cnt][0] = $myrow[0]; 
         			$xdata[$cnt][1] = $myrow[1]; 
         			++$cnt;
      			}
   			}	
		}
		else
			echo "Error in getPortDataSet";

   		return $cnt;
	}
	
	/*对是哪种类型的协议进行分析
	function getClassificationDataSet(&$xdata, $chart_type, $min_threshold, $criteria){
		$sql = "SELECT DISTINCT sig_class_id, COUNT(signature.cid) ".
        "FROM signature ".$criteria[0].
        "WHERE ".$criteria[1].
        " GROUP BY sig_class_id ORDER BY sig_class_id";
		 
		$cnt = 0;
		$result = $this->DB->Execute($sql);
			 
		if($result)
		{
   			while ($myrow = $result->FetchRow() )
   			{
      			if ( $myrow[1] >= $min_threshold )
      			{
         			$xdata[$cnt][0] = strip_tags(getSigClassName($myrow[0], $this->DB)); 
         			$xdata[$cnt][1] = $myrow[1]; 
         			++$cnt;
      			}
   			}	
		}
		else
			echo "Error in getClassificationDataSet";

   		return $cnt;
	}
	*/
	function getSensorDataSet(&$xdata, $chart_type, $time_start, $time_end){
		/*
		print_r($time_start);
		print_r($time_end);
		*/
		$isStart = $this->checkTime($time_start);
		$isEnd = $this->checkTime($time_end);
		
		if($isStart == "1" && $isEnd == "1")
		{
			$sql = "SELECT DISTINCT event.sid, COUNT(event.cid) ".
          	"FROM event "."WHERE timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
			"AND timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
          	" GROUP BY event.sid ORDER BY event.sid";
			
			//print($sql);
		}
		else if($isStart == "1")
		{
			$sql = "SELECT DISTINCT event.sid, COUNT(event.cid) ".
          	"FROM event "."WHERE timestamp > "."'$time_start[3]-$time_start[2]-$time_start[1] "."$time_start[0]:00:00'".
          	" GROUP BY event.sid ORDER BY event.sid";
			
			//print($sql);
		}
		else if($isEnd == "1")
		{
			$sql = "SELECT DISTINCT event.sid, COUNT(event.cid) ".
          	"FROM event "."WHERE timestamp < "."'$time_end[3]-$time_end[2]-$time_end[1] "."$time_end[0]:00:00'".
          	" GROUP BY event.sid ORDER BY event.sid";
			
			//print($sql);
		}
		else
		{
			$sql = "SELECT DISTINCT event.sid, COUNT(event.cid) ".
          	"FROM event ".
          	" GROUP BY event.sid ORDER BY event.sid";
			
			//print($sql);
		}
		
		$cnt = 0;
		$result = $this->DB->Execute($sql);
			 
		if($result)
		{
   			while ($myrow = $result->FetchRow() )
   			{
      			if ( $myrow[1] >= $min_threshold )
      			{
      				
      				$result2 = $this->DB->Execute("SELECT hostname FROM sensor where sid=".$myrow[0]);
         			$sensor_name = $result2->FetchRow();
         			$xdata[$cnt][0] = $sensor_name[0];
         			$xdata[$cnt][1] = $myrow[1]; 
         			++$cnt;
      			}
   			}	
		}
		else
			echo "Error in getSensorDataSet";

   		return $cnt;
	}
	
	function agLong2IP($long_IP)
	{
   		$tmp_IP = $long_IP;
   		if ( $long_IP > 2147483647 )
   		{
      		$tmp_IP = 4294967296 -  $tmp_IP;
      		$tmp_IP = $tmp_IP * (-1); 
   		}

   		$tmp_IP = long2ip($tmp_IP);
   		return $tmp_IP;
	}
	
	function getSignatureName($sig_id, $db)
	{
   		$name = "";

   		$temp_sql = "SELECT sig_name FROM signature WHERE sig_id='$sig_id'";
   		$tmp_result = $this->DB->Execute($temp_sql);
   		if ( $tmp_result )
   		{
      		$myrow = $tmp_result->FetchRow();
      		$name = $myrow[0];
   		}
  		else
      		$name = "[SigName unknown]";

   		return $name;
	}
	
	function checkTime($time_group)
	{
		
		//print($time_group);
		
		if($time_group[0]!=" "&&$time_group[1]!=" "&&$time_group[2]!=" " &&$time_group[3]!=" ")
       	{
       		return true;
       	}
       	
       	return false;
	}
	function StoreAlertNum($sql, $label, &$xdata, &$cnt, $min_threshold)
	{  
		//print($sql);
  		$result = $this->DB->Execute($sql);
  		
  		if($result){
  			while ( $myrow = $result->FetchRow() )
  			{
     			if ( $myrow[0] >= $min_threshold )
     			{
        			$xdata [ $cnt ][0] = $label;
        			$xdata [ $cnt ][1] = $myrow[0];
     			}
     			$cnt++;
  			}
  		}
  	
  }

}
?>