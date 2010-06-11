<h5><?php echo $admin[124]; ?></h5>

<script type="text/javascript" src="js/prototype.js"></script>
<script type="text/javascript" src="js/scriptaculous.js"></script>

<?php
if($_GET['type_2']=='install' && $_GET['id']!=''){
	echo '<div class="submit_form">'.$PLUGIN->install_block($_user_active['id'], $_GET['id']).'</div>';
}
elseif($_GET['type_2']=='uninstall' && $_GET['id']!=''){
	echo '<div class="submit_form">'.$PLUGIN->uninstall_block($_user_active['id'], $_GET['id']).'</div>';
}

$block_id=$PLUGIN->get_block_to_install($_user_active['id']);
if (count($block_id)>0){
?>
<table id="manage_blocks" class="default_table">
  <tr>
    <th><?php echo $admin[11]; ?></th>
    <th><?php echo $admin[105]; ?></th>
	<th><?php echo $admin[106]; ?></th>
	<th><?php echo $admin[60]; ?></th>
  </tr>

<?php
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
		
		echo '</td><td>'.$plugin_selected['name'].'</td><td><a href="?action=settings&amp;type=manage_block&amp;type_2=install&amp;id='.$value.'"><img src="images/install.png" alt="'.$admin[134].'" title="'.$admin[134].'" /></a></td></tr>';
	}

?>
</table>
<?php
}
?>


<ul id="block_list" class="sortable-list">
<?php
$block_list = $PLUGIN->get_block_order($_user_active['id']);
foreach ($block_list as $block_id => $title){
	$block_selected=$PLUGIN->get_block_settings($block_id);
	$plugin_selected=$PLUGIN->get_plugin($block_selected['plugin_id']);
?>
	<li id="block_<?php echo $block_id; ?>">
	<?php
	echo $title['name'];
	echo '<div class="small"><span class="bold">'.$admin[50].': </span>'.$title['description'].'</div>';
	echo '<div class="small"><span class="bold">'.$admin[106].': </span>'.htmlspecialchars($plugin_selected['name']).'</div>';
	echo '<div class="small"><span class="bold">'.$admin[105].': </span>';
	$iptables_list=$PLUGIN->get_iptables_list($block_id);	
	foreach($iptables_list as $iptables_id){
		$iptables_array=$IPTABLES->get_iptables($iptables_id);
		echo htmlspecialchars($iptables_array['name']).' ';
	}
	echo '</div>';
	echo '<div class="small"><span class="bold">'.$admin[60].': </span><a href="?action=settings&amp;type=manage_block&amp;type_2=uninstall&amp;id='.$block_id.'"><img src="images/delete.png" alt="'.$admin[139].'" title="'.$admin[139].'" /></a></div>'

	?>
	</li>
<?php
}
?>
</ul>

<script type="text/javascript">
function updateOrder(){
	var handlerFunc = function(t){
		alert(t.responseText);
	}

	var errFunc = function(t) {
		alert('Error ' + t.status + ' -- ' + t.statusText);
	}

	var options ={
		method : 'post',
		parameters : 'user_id=<?php echo base64_encode($SESSION->user_id()); ?>&' + Sortable.serialize('block_list'),
		onComplete:function(request){new Effect.Highlight('block_list',{startcolor:'#FFCCCD', endcolor:'#FFFFFF'})}
	};
	new Ajax.Request('processor', options);
}

Sortable.create('block_list', { onUpdate : updateOrder, ghosting:false,constraint:false });
</script>