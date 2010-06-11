<?
$optimize_row=$DB->GetRow("SELECT * FROM `".$_ulogd_table."` order by oob_time_sec ASC limit 0,1");
if (@$optimize_row['oob_time_sec']!=""){
	$optimize_limit=mktime(0,0,0,date("n"),date("j")-OPTIMIZE_DAY,date("Y"));
	
	foreach($iptables_settings as $iptables_id=>$iptables_value){
		$j=0;$optimize_hour_start=0;$optimize_log_tot=0;
		$optimize_hour_stop=mktime(0,0,0,date("n",$optimize_row['oob_time_sec']),date("j",$optimize_row['oob_time_sec']),date("Y",$optimize_row['oob_time_sec']));
		while($optimize_hour_stop<$optimize_limit){
			$optimize_hour_start=mktime($j,0,0,date("n",$optimize_row['oob_time_sec']),date("j",$optimize_row['oob_time_sec']),date("Y",$optimize_row['oob_time_sec']));
			$j=$j+1;
			$optimize_hour_stop=mktime($j,0,0,date("n",$optimize_row['oob_time_sec']),date("j",$optimize_row['oob_time_sec']),date("Y",$optimize_row['oob_time_sec']));
			$optimize_log_tot=$DB->GetRow("SELECT COUNT(*) FROM `".$_ulogd_table."` WHERE (oob_time_sec>='$optimize_hour_start' AND oob_time_sec<'$optimize_hour_stop') AND oob_prefix='".$iptables_value['name']."'");
			$optimize_log_tot=$optimize_log_tot[0];
			$DB->Execute("INSERT INTO `".$iptables_value['name']."` (timelog, countlog) VALUES ('$optimize_hour_start', '$optimize_log_tot') ");
		}
	}
	$DB->Execute("DELETE FROM `".$_ulogd_table."` WHERE oob_time_sec<'$optimize_limit'");
}
?>