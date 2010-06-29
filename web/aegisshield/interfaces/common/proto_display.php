<br />
<?php 
	echo $admin[450];
?>
<table>
<tr>
<td>
<?php 
	$cnt = 0;
	$cnt = $APPROTO->getProtoDataSet($xdata);
	
	if($cnt == 0){
		echo $admin[451];
	}else
		echo "<img src=\"interfaces/common/proto_display_pie.php\" />";
?>
</td>
</tr>
</table>