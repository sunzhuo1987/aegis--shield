<br />
<?php 
	echo "proto infomation";
?>
<table>
<tr>
<td>
<?php 
	$cnt = 0;
	$cnt = $APPROTO->getProtoDataSet($xdata);
	
	if($cnt == 0){
		echo "No data";
	}else
		echo "<img src=\"interfaces/common/proto_display_pie.php\" />";
?>
</td>
</tr>
</table>