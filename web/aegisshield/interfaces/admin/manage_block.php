<h4><?php echo $admin[91]; ?></h4>

<?php
switch($_GET['type']){
	case 'configure':
		$block_selected=$PLUGIN->get_block_settings($_GET['id']);
		$settings=unserialize($block_selected['settings']);
		$plugin_selected=$PLUGIN->get_plugin($block_selected['plugin_id']);
		
		if ($_POST['send']==$admin[35]){
			if($_POST[$plugin_selected.'_count']>=0){
				$count_plugin_selected=$_POST[$plugin_selected['folder'].'_count'];
				$plugin_count=1;
				$tmp_plugin_array=array();
				while ($plugin_count <= $count_plugin_selected){
					if ($_POST[$plugin_selected['folder'].'_'.$plugin_count]==''){
						$plugin_error=true;
					}
					$tmp_plugin_array[$plugin_selected['folder'].'_'.$plugin_count]=$_POST[$plugin_selected['folder'].'_'.$plugin_count];
					$plugin_count++;
				}
				$serialize_var=array('name'=> $_POST['name'], 'description'=> $_POST['description']);
				$new_serialize=serialize(array_merge($serialize_var,$tmp_plugin_array));
			}
			else{
				$new_serialize=serialize(array('name'=> $_POST['name'], 'description'=> $_POST['description']));
			}

			if ($plugin_error){
				$block_array=array('id'=>$_GET['id']);
			}
			else{
				$block_array=array('id'=>$_GET['id'], 'iptables'=>$_POST['iptables'], 'groups'=>$_POST['groups'], 'public'=>$_POST['public'], 'var_serialized'=>$new_serialize);
			}
			echo '<div class="submit_form">'.$PLUGIN->set_block($block_array).'</div>';
		}
		else{
?>

<form method="post" action="">
<table id="add_block" class="default_table">
<tr><td><?php echo $admin[106]; ?> * </td><td><?php echo htmlspecialchars($plugin_selected['name']); ?></td></tr>
<tr><td><?php echo $admin[105]; ?> * </td><td><?php echo $IPTABLES->get_iptables_checkbox($PLUGIN->get_iptables_list($_GET['id'])); ?></td></tr>
<tr><td><?php echo $admin[107]; ?> * </td><td><?php echo $GROUP->get_group_checkbox($PLUGIN->get_group_list($_GET['id'], false)); ?></td></tr>
<tr><td><?php echo $admin[108]; ?> * </td><td><?php echo $PLUGIN->account_list($_GET['id']); ?></td></tr>
<tr><td><?php echo $admin[11]; ?> * </td><td><input type="text" name="name" value="<?php echo htmlspecialchars($settings['name']); ?>" /></td></tr>
<tr><td><?php echo $admin[50]; ?></td><td><textarea name="description" rows="" cols=""><?php echo htmlspecialchars($settings['description']); ?></textarea></td></tr>

<?php
if(file_exists('plugin/'.$plugin_selected['folder'].'/blocks.php')){
	require_once('plugin/'.$plugin_selected['folder'].'/lang/'.$_user_active['language'].'/dictionary.php');
	require_once('plugin/'.$plugin_selected['folder'].'/blocks.php');
	if(function_exists($plugin_selected['folder'].'_view_blocks')){
		$n_plugin_var=call_user_func($plugin_selected['folder'].'_get_var');
		$tmp_array_plugin=array();
		$plugin_count=1;
		while ($plugin_count <= $n_plugin_var){
			$tmp_array_plugin[$plugin_count]=htmlspecialchars($settings[$plugin_selected['folder'].'_'.$plugin_count]);
			$plugin_count++;
		}
		$buffer_adv_sett.=call_user_func($plugin_selected['folder'].'_set_blocks',$tmp_array_plugin);
	}
	echo $buffer_adv_sett;
}
?>

<tr><td>&nbsp;</td><td><br /><input type="submit" name="send" value="<?php echo $admin[35]; ?>" /></td></tr>
</table>
</form>

<br />
<div class="center">* <?php echo $admin[42]; ?></div>

<?php
		}
	break;
	case 'delete':
		if ($_POST['send']==$admin[33]){
			echo '<div class="submit_form">'.$PLUGIN->del_block($_GET['id']).'</div>';
		}
		elseif($_POST['send']==$admin[34]){
			echo '<div class="submit_form">'.$admin[101].'</div>';
		}
		else{
?>

<h5><?php echo $admin[111]; ?></h5>
<form method="post" action="">
<table id="delete_block" class="default_table">
<tr class="center"><td><input type="submit" name="send" value="<?php echo $admin[33]; ?>" /></td><td><input type="submit" name="send" value="<?php echo $admin[34]; ?>" /></td>
</tr></table>
</form>

<?php
		}
	break;
	default:
?>
<script type="text/javascript">
function setMicrocat(chooser) {
    var choice = chooser.options[chooser.selectedIndex].value;
<?php
$buffer_js_array='plugin=new Array(';
$plugins_id=$PLUGIN->get_plugins_id();
foreach($plugins_id as $plugin_value){
	$plugin_info=$PLUGIN->get_plugin($plugin_value['id']);
	if(file_exists('plugin/'.$plugin_info['folder'].'/blocks.php')){
		require_once('plugin/'.$plugin_info['folder'].'/lang/'.$_user_active['language'].'/dictionary.php');
		require_once('plugin/'.$plugin_info['folder'].'/blocks.php');
		if(function_exists($plugin_info['folder'].'_view_blocks')){
			$buffer_js_array.="'".$plugin_value['id']."', ";
		}
	}
}
$buffer_js_array.=');';
$buffer_js_array=str_replace("', )", "')", $buffer_js_array);
echo "	".$buffer_js_array."\n";
?>
	var length_plugin=plugin.length;
	var check;
	for(i=0; i<length_plugin; i++){
		if(choice==plugin[i]){
			check=true;
		}
		else{
		document.getElementById('ID_'+plugin[i]).style.display='none';
		}
	}
	
	if (check){
		document.getElementById('ID_'+choice).style.display='block';
	}
}
</script>
<?php
if(@$_POST['send']==$admin[104]){
	$tmp_plugin_name=$PLUGIN->get_plugin($_POST['plugin_list']);
	if ($_POST[$tmp_plugin_name['folder'].'_count']>=0){
		$tmp_plugin_selected=$tmp_plugin_name['folder'];
		$count_plugin_selected=$tmp_plugin_selected.'_count';
		$count_plugin_selected=$_POST[$count_plugin_selected];
		$count_plugin_selected=str_replace($tmp_plugin_selected.'_','',$count_plugin_selected);
		$plugin_count=1;
		$tmp_plugin_array=array();
		while ($plugin_count <= $count_plugin_selected){
			if ($_POST[$tmp_plugin_selected.'_'.$plugin_count]==''){
				$plugin_error=true;
			}
			$tmp_plugin_array[$tmp_plugin_selected.'_'.$plugin_count]=$_POST[$tmp_plugin_selected.'_'.$plugin_count];
			$plugin_count++;
		}

		$serialize_var=array('name'=> $_POST['name'], 'description'=> $_POST['description']);
		$new_serialize=serialize(array_merge($serialize_var,$tmp_plugin_array));
	}
	else{
		$new_serialize=serialize(array('name'=> $_POST['name'], 'description'=> $_POST['description']));
	}
	
	if ($plugin_error){
		$block_array=array();
	}
	else{
		$block_array=array('plugin_list'=> $_POST['plugin_list'], 'iptables'=> $_POST['iptables'], 'groups'=> $_POST['groups'], 'public'=> $_POST['public'], 'var_serialized'=> $new_serialize);
	}
	
	echo '<div class="submit_form">'.$PLUGIN->add_block($block_array).'</div>';
}
?>

<table id="manage_block" class="default_table">
  <tr>
    <th><?php echo $admin[11]; ?></th>
    <th><?php echo $admin[105]; ?></th>
    <th><?php echo $admin[107]; ?></th>
	<th><?php echo $admin[106]; ?></th>
	<th><?php echo $admin[108]; ?></th>
	<th><?php echo $admin[60]; ?></th>
  </tr>

<?php
	$block_id=$PLUGIN->get_blocks_id('all');
	foreach($block_id as $value){
		$block_selected=$PLUGIN->get_block_settings($value);
		$plugin_selected=$PLUGIN->get_plugin($block_selected['plugin_id']);
		$settings=unserialize($block_selected['settings']);
		echo '<tr><td>'.$settings['name'].'</td><td>';

		$iptables_list=$PLUGIN->get_iptables_list($block_selected['id']);
		foreach($iptables_list as $iptables_id){
			$iptables_selected=$IPTABLES->get_iptables($iptables_id);
			echo $iptables_selected['name'].'<br />';
		}
		
		echo '</td><td>';
		$group_list=$PLUGIN->get_group_list($block_selected['id'],'public');
		foreach($group_list as $group_id){
			$group_selected=$GROUP->get_group($group_id);
			echo $group_selected['name'].'<br />';
		}
		
		echo '</td><td>'.$plugin_selected['name'].'</td><td>'.$PLUGIN->is_public_block_text($block_selected['id']).'</td><td>'.$PLUGIN->block_option_list($block_selected['id']).'</td></tr>';
	}

?>
</table>

<br /><br />

<form method="post" action="">
<table id="add_block" class="default_table">
<tr><td><?php echo $admin[106]; ?> * </td><td><?php echo $PLUGIN->get_plugin_select(); ?></td></tr>
<tr><td><?php echo $admin[105]; ?> * </td><td><?php echo $IPTABLES->get_iptables_checkbox(); ?></td></tr>
<tr><td><?php echo $admin[107]; ?> * </td><td><?php echo $GROUP->get_group_checkbox(); ?></td></tr>
<tr><td><?php echo $admin[108]; ?> * </td><td><?php echo $PLUGIN->account_list(); ?></td></tr>
<tr><td><?php echo $admin[11]; ?> * </td><td><input type="text" name="name" value="" /></td></tr>
<tr><td><?php echo $admin[50]; ?></td><td><textarea name="description" rows="" cols=""></textarea></td></tr>

<?php 
	$plugins_id=$PLUGIN->get_plugins_id();
	$buffer_adv_sett='';
	foreach($plugins_id as $plugin_value){
		$plugin_info=$PLUGIN->get_plugin($plugin_value['id']);
		if(file_exists('plugin/'.$plugin_info['folder'].'/blocks.php')){
			require_once('plugin/'.$plugin_info['folder'].'/lang/'.$_user_active['language'].'/dictionary.php');
			require_once('plugin/'.$plugin_info['folder'].'/blocks.php');
			if(function_exists($plugin_info['folder'].'_view_blocks')){
				$buffer_adv_sett.='<tr><td colspan="2"><table id="ID_'.$plugin_value['id'].'" style="display:none;z-index:10;">'.call_user_func($plugin_info['folder'].'_view_blocks').'</table></td></tr>';
			}
		}
	}
	
	if($buffer_adv_sett!=''){
		echo '<tr><td colspan="2" class="center bold"><br />'.$admin[143].'</td></tr>'.$buffer_adv_sett;
	}
?>

<tr><td>&nbsp;</td><td><br /><input type="submit" name="send" value="<?php echo $admin[104]; ?>" /></td></tr>
</table>
</form>

<br />
<div class="center">* <?php echo $admin[42]; ?></div>

<?php
}
?>