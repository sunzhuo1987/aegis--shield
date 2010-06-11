<?php
//Group class
class group{

	var $DB;
	
	//Constructor
	function group($DB){
		$this->DB = $DB;
	}
	
	//Check if a group exists
	function exist_group($id){
		$id=(int)$id;
		$row = $this->DB->GetRow("SELECT * FROM `".DB_PREFIX."groups` WHERE `id`='$id'");
		$tot=count($row);
		if ($tot>0){
			return true;
		}
		else{
			return false;
		}
	}
	
	//Get groups list
	function groups_list($group=false){
		$groups=$this->get_groups_id();
		$buffer='<select name="group_id">';
		
		foreach ($groups as $key => $value){
			if ($group==$value['id']){
				$buffer.='<option selected="selected" value="'.$value['id'].'">'.htmlspecialchars($value['name']).'</option>';
			}
			else{
				$buffer.='<option value="'.$value['id'].'">'.htmlspecialchars($value['name']).'</option>';
			}
		}
		$buffer.='</select>';
		return $buffer;
	}
	
	//Get groups array
	function get_groups_id(){
		$groups=array();
		$rs = & $this->DB->Execute("SELECT * FROM `".DB_PREFIX."groups`");
		while (!$rs->EOF) {
			$groups[]=$rs->fields;
			$rs->MoveNext();
		}
		return $groups;
	}

	//Add a group
	function add_group($group_array){
		if ($group_array['name']==''){
			return $GLOBALS['admin'][53].'<br />'.$GLOBALS['admin'][44];
		}
		$this->DB->Execute("INSERT INTO `".DB_PREFIX."groups` (`name`, `description`) VALUES ('".$group_array['name']."', '".$group_array['description']."')");
		return $GLOBALS['admin'][54];
	}
	
	//Set a group
	function set_group($group_array){
		if ($this->exist_group($group_array['id'])){
			if ($group_array['name']==''){
				return $GLOBALS['admin'][75].'<br />'.$GLOBALS['admin'][44];
			}
			$this->DB->Execute("UPDATE `".DB_PREFIX."groups` SET `name`='".$group_array['name']."', `description`='".$group_array['description']."' WHERE `id`='".$group_array['id']."'");
			return $GLOBALS['admin'][59];
		}
		return 'Gorup doesn\'t exist (set_group)';
	}
	
	//Delete a group
	function del_group($id){
		$id=(int)$id;
		if ($this->exist_group($id)){
			$users=$this->get_users($id);
			foreach ($users as $value){
				$USER_TMP = new user(&$this->DB);
				$USER_TMP->del_user($value['id']);
				unset($USER_TMP);
			}
			$this->DB->Execute("DELETE FROM `".DB_PREFIX."block_groups` WHERE `group_id`='$id'");
			$this->DB->Execute("DELETE FROM `".DB_PREFIX."groups` WHERE `id`='$id'");
			return $GLOBALS['admin'][100];
		}
		else{
			return 'Group doesn\'t exist (del group)';
		}
	}
	
	//Get a group
	function get_group($id){
		$id=(int)$id;
		if ($this->exist_group($id)){
			return $this->DB->GetRow("SELECT * FROM `".DB_PREFIX."groups` WHERE `id`='$id'");
		}
		exit('Group doesn\'t exist (get_group)');
	}
	
	//Get user_id list in a group
	function get_users($id){
		$id=(int)$id;
		if ($this->exist_group($id)){
			$users=array();
			$rs = & $this->DB->Execute("SELECT id FROM `".DB_PREFIX."users` WHERE `group_id`='$id'");
			while (!$rs->EOF) {
				$users[]=$rs->fields;
				$rs->MoveNext();
			}
			return $users;	
		}
		exit('Group doesn\'t exist (get_users)');
	}
	
	//Get option list
	function option_list($id){
		$id=(int)$id;
		if ($this->exist_group($id)){
			$buffer='<a href="admin.php?action=manage_group&amp;type=configure&amp;id='.$id.'"><img src="images/configure.png" alt="'.$GLOBALS['admin'][78].'" title="'.$GLOBALS['admin'][78].'" /></a> <a href="admin.php?action=manage_group&amp;type=delete&amp;id='.$id.'"><img src="images/delete.png" alt="'.$GLOBALS['admin'][51].'" title="'.$GLOBALS['admin'][51].'" /></a> <a href="admin.php?action=manage_group&amp;type=view&amp;id='.$id.'"><img src="images/information.png" alt="'.$GLOBALS['admin'][76].'" title="'.$GLOBALS['admin'][76].'" /></a>';
			return $buffer;
		}		
		return 'Group doesn\'t exist (option_list)';
	}
		
	//Get group checkbox
	function get_group_checkbox($array_group=false){
		$buffer='';
		$groups_id=$this->get_groups_id();
		foreach ($groups_id as $value){
			$group_selected=$this->get_group($value['id']);
			$tmp_checkbox='';
			if ($array_group!=false){
				foreach ($array_group as $value_group){
					if ($value_group==$group_selected['id']){
						$tmp_checkbox='checked="checked" ';
					}
				}
			}
			
			$buffer.='<input name="groups[]" type="checkbox" class="no_width" value="'.$group_selected['id'].'" '.$tmp_checkbox.'/> '.$group_selected['name'].'<br />';
		}
		return $buffer;
	}

}
?>