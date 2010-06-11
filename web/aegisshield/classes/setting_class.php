<?php
//Setting class
class setting{

	var $DB;
	
	//Constructor
	function setting($DB){
		$this->DB = $DB;
	}
	
	//Get the setting value
	function get_value($name){
		$row = $this->DB->GetRow("SELECT `value` FROM `".DB_PREFIX."settings` WHERE `name`='$name'");
		return $row['value'];
	}
	
	//Set the setting value
	function set_value($name, $value=false){
		$res=$this->DB->Execute("UPDATE `".DB_PREFIX."settings` SET `value`='".$value."' WHERE `name`='$name'");
	}
	
	//Delete the setting value
	function del_setting($name){
		$this->DB->Execute("DELETE FROM `".DB_PREFIX."settings` WHERE `name`='$name'");
	}
	
	//Add setting value
	function add_setting($name, $value){
		$this->DB->Execute("INSERT INTO `".DB_PREFIX."settings` (`name`, `value`) VALUES ('".$name."', '".$value."')");
	}
	
	//Is public
	function is_public(){
		$buffer.='<select name="public"><option value="yes"><?php echo $admin[33]; ?></option><option value="no"><?php echo $admin[34]; ?></option></select>';
		return $buffer;
	}

	//Make dynamic select
	function create_select($name, $values, $enabled, $default=false){
		if ($enabled){
			$buffer='<select name="'.$name.'">';
		}
		else{
			$buffer='<select name="'.$name.'" disabled="disabled">';
		}
		
		foreach ($values as $key => $value){
			if ($default==$value['key']){
				$buffer.='<option selected="selected" value="'.$value['key'].'">'.$value['name'].'</option>';
			}
			else{
				$buffer.='<option value="'.$value['key'].'">'.$value['name'].'</option>';
			}
		}
		$buffer.='</select>';
		return $buffer;
	}
	
	//Database select
	function database_select($db, $enabled){
		$dblist=array(array('key'=>'mysql', 'name'=>'mysql'), array('key'=>'postgres', 'name'=>'postgres'), array('key'=>'postgres', 'name'=>'postgres'), array('key'=>'sqlite', 'name'=>'sqlite'), array('key'=>'oci8', 'name'=>'oci8'), array('key'=>'postgres', 'name'=>'postgres'), array('key'=>'postgres64', 'name'=>'postgres64'), array('key'=>'postgres7', 'name'=>'postgres7'), array('key'=>'postgres8', 'name'=>'postgres8'));
		return $this->create_select('database', $dblist, $enabled, $db);	
	}
	
	//Check if a file can be changed
	function is_modifiable($file_name){
		if (is_writable($file_name)){
			return true;
		}
		return false;
	}
	
}
?>