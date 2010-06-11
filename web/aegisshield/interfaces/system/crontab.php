<?php
//Load dictionary
if ($_user_active['language']==''){
	$_user_active['language']=$SETTING->get_value('language');
}
$language_file='lang/'.$_user_active['language'].'/dictionary.php';
if (file_exists($language_file)){
	require_once($language_file);
}
else{
	exit('NO Dictionary!');
}
echo $PAGE->getHeader('system','System');

	//Load block view
	$crontab_list=$PLUGIN->get_blocks_array($_user_active['id']);
	if(count($crontab_list)>=1){
		$crontab_check=true;
		foreach($crontab_list as $block_selected){
		
			$block_info=$PLUGIN->get_block_settings($block_selected['block_id']);
			$plugin_info=$PLUGIN->get_plugin($block_info['plugin_id']);
			$block_info_text=unserialize($block_info['settings']);
			
			$iptables_settings=array();
			foreach($block_selected['iptables_id'] as $value_iptables){
				$ipt_tmp=$IPTABLES->get_iptables($value_iptables);
				$iptables_settings[]=array('name'=>$ipt_tmp['name'], 'name_web'=>$ipt_tmp['name_web'], 'color'=>$ipt_tmp['color'], 'other'=>$ipt_tmp['other']);
			}
		
			$crontab_lang=$_user_active['language'];
			//Load Plugin
			echo '<div class="plugin_title">'.$block_info_text['name'].'</div>';
			echo '<div class="plugin_description">'.$block_info_text['description'].'</div>';
			require('plugin/'.$plugin_info['folder'].'/index.php');
		}
		require_once('interfaces/system/optimize.php');
	}
	
echo $PAGE->getFooter();
?>