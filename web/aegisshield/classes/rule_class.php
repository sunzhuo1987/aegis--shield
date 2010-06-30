<?php
//rule class
class rule {

	var $DB;

	//Constructor
	function rule($DB){
		$this->DB = $DB;
	}
	
	//Check if a rule exists
	function exist_rule($id){
		$id=(int)$id;
		$row = $this->DB->GetRow("SELECT * FROM custom_rule WHERE `id`='$id'");
		$tot=count($row);
		if ($tot>0){
			return true;
		}
		else{
			return false;
		}
	}
	
	//Add a new rule
	function add_rule($rule_array){
		if ($rule_array['type']=='' || $rule_array['rule']==''){
			return $GLOBALS['admin'][487];
		}
		
		if($rule_array['proto']=='')
		{
			$sql = "INSERT INTO custom_rule (`type`, `rule`, `proto`) VALUES (".$rule_array['type'].", '".$rule_array['rule']."', 'NULL')";
		}else
			$sql = "INSERT INTO custom_rule (`type`, `rule`, `proto`) VALUES (".$rule_array['type'].", '".$rule_array['rule']."', '".$rule_array['proto']."')";
			
		$this->DB->Execute($sql);
		
		return $GLOBALS['admin'][486];
	}
	
	//Change rule
	function change_rule($id, $rule){
		$id=(int)$id;
		if ($this->exist_rule($id)){
			$this->DB->Execute("UPDATE custom_rule SET `rule`='".$rule."' WHERE `id`='$id'");
			return 'Rule updated!';
		}
		return 'Rule Not updated! Call Administrator...';
	}
	
	
	
	//Delete a rule
	function del_rule($id){
		$id=(int)$id;
		if ($this->exist_rule($id)){
			$this->DB->Execute("DELETE FROM custom_rule WHERE `id`='$id'");
			return $GLOBALS['admin'][477];
		}
		else{
			return 'User doesn\'t exist (del_rule)';
		}
	}
	
	
	//Get rule info
	function get_rule($id){
		$id=(int)$id;
		if ($this->exist_rule($id)){
			return $this->DB->GetRow("SELECT * FROM custom_rule WHERE id='$id'");
		}
		exit('User doesn\'t exist (get_rule)');
	}
	

	//Get id of all rules
	function get_rules_id(){
		$rules=array();
		$rs = & $this->DB->Execute("SELECT `id` FROM custom_rule");
		while (!$rs->EOF){
			$rules[]=$rs->fields;
			$rs->MoveNext();
		}
		return $rules;
	}
	
	//Get option list int admin interface
	function option_list_admin($id){
		$id=(int)$id;
		if ($this->exist_rule($id)){
			$buffer='<a href="admin.php?action=manage_rules&amp;type=delete_rule&amp;id='.$id.
			'"><img src="images/delete.png" alt="'."Delete the rule".'" title="'."Delete the rule".
			'" /></a> <a href="admin.php?action=manage_rules&amp;type=change_rule&amp;id='.$id.
			'"><img src="images/update.png" alt="'."Change the rule".'" title="'."Change the rule".'" /></a>';
			return $buffer;
		}
		return 'User doesn\'t exist (option_list)';
	}
	
	//Get option list in user interface
	function option_list_user($id){
		$id=(int)$id;
		if ($this->exist_rule($id)){
			$buffer='<a href="user.php?action=manage_rules&amp;type=delete_rule&amp;id='.$id.
			'"><img src="images/delete.png" alt="'."Delete the rule".'" title="'."Delete the rule".
			'" /></a> <a href="user.php?action=manage_rules&amp;type=change_rule&amp;id='.$id.
			'"><img src="images/update.png" alt="'."Change the rule".'" title="'."Change the rule".'" /></a>';
			return $buffer;
		}
		return 'User doesn\'t exist (option_list)';
	}
}
?>