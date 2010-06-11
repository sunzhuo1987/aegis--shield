<?php 
	//require_once('includes/config.php');
?>
<br />
<table>
<tr><td>
<?php 
	$sensorCnt=$ALERTS->sensorCnt();
	$uniqueAlerts = $ALERTS->uniqueAlertCnt();
	$eventCnt = $ALERTS->eventCnt();
	$ipSrcCnt = $ALERTS->uniqueIpSrcCnt();
	$ipDstCnt = $ALERTS->uniqueIpDstCnt();
	$linkCnt = $ALERTS->uniqueLinkCnt();
	$srcP = $ALERTS->uniqueSrcPortCnt();
	$tcpSrcP = $ALERTS->uniqueTcpSrcPortCnt();
	$udpSrcP = $ALERTS->uniqueUdpSrcPortCnt();
	$dstP = $ALERTS->uniqueDstPortCnt();
	$tcpDstP = $ALERTS->uniqueTcpDstPortCnt();
	$udpDstP = $ALERTS->uniqueUdpDstPortCnt();
	
	
	echo 'Sensors:'.$sensorCnt.'<br />';
	echo 'Unique Alerts:'.$uniqueAlerts.'<br />';
	echo 'Total Number of Alerts:'.$eventCnt.'<br />';
	echo '<br />';
	echo '  Source IP address:'.$ipSrcCnt.'<br />';
	echo '  Dest IP address:'.$ipDstCnt.'<br />';
	echo '  Unique IP links:'.$linkCnt.'<br />';
	echo '<br />';
	echo '  Source Ports:'.$srcP.'<br />';
	echo '    .TCP('.$tcpSrcP.') UDP('.$udpSrcP.')'.'<br />';
	echo '  Dest Ports:'.$dstP.'<br />';
	echo '    .TCP('.$tcpDstP.') UDP('.$udpDstP.')'.'<br />';
	
?>
</td>
<td>
<?php 
	echo "<img src=\"interfaces/common/general_display.php\" />";
?>
</td></tr>
</table>

