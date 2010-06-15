<h4><?php echo $admin[9]; ?></h4>
<?php
echo '<h5>'.$admin[148].'</h5><div class="small left" id="info_system">';
echo $admin[149].': '.$SETTING->get_value('iptablesweb_version').'<br />';
echo $admin[150].': '.$SYSTEM_INFO->GetUptime().'<br />';
echo $admin[151].': '.date("l dS of F Y h:i:s A").'<br />';
echo $admin[152].': '.phpversion().'<br />';
echo $admin[153].': '.$SYSTEM_INFO->GetKernelVersion().'<br />';
echo $admin[154].': '.$SYSTEM_INFO->getDistroInfo().'</div>';
echo '<br /><br /><br />';
?>

<?php
echo '<h5>'.$admin[146].'</h5>';
?>
<table id="database_info">
<tr>
<th>Nome</th><th>Righe</th><th>Dimensione</th><th>Aggiornato il</th>
</tr>
<?php
$rs = & $DB->Execute("SHOW TABLE STATUS FROM $_db_name");
$counter_table=0;$size_table=0;$rows_table=0;
while (!$rs->EOF){
	$db_info=$rs->fields;
	$size_rows=$db_info['Data_length']+$db_info['Index_length'];
	$size_table=$size_table+$size_rows;
	$rows_table=$rows_table+$db_info['Rows'];
	echo '<tr><td>'.$db_info['Name'].'</td><td>'.$db_info['Rows'].'</td><td>'.$size_rows.' bytes</td><td>'.$db_info['Update_time'].'</td></tr>';
	$counter_table++;
	$rs->MoveNext();
}

echo '<tr class="bold"><td>'.$counter_table.' '.$admin[147].'</td><td>'.$rows_table.'</td><td>'.$size_table.' bytes</td><td>---</td></tr></table>';
echo '<br /><br /><br />';
?>
</table>