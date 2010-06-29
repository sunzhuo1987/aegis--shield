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
	
	
	echo $admin[270].':'.$sensorCnt.'<br />';
	echo $admin[271].':'.$uniqueAlerts.'<br />';
	echo $admin[272].':'.$eventCnt.'<br />';
	echo '<br />';
	echo '  '.$admin[273].':'.$ipSrcCnt.'<br />';
	echo '  '.$admin[274].':'.$ipDstCnt.'<br />';
	echo '  '.$admin[275].':'.$linkCnt.'<br />';
	echo '<br />';
	echo '  '.$admin[276].':'.$srcP.'<br />';
	echo '    .TCP('.$tcpSrcP.') UDP('.$udpSrcP.')'.'<br />';
	echo '  '.$admin[279].':'.$dstP.'<br />';
	echo '    .TCP('.$tcpDstP.') UDP('.$udpDstP.')'.'<br />';
	
?>
</td>
<td>
<?php 
	echo "<img src=\"interfaces/common/general_display.php\" />";
?>
</td></tr>
</table>