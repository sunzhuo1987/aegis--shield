<?php
//User class
class rule {

	var $DB;

	//Constructor
	function rule($DB){
		$this->DB = $DB;
	}
	
	//Check if a rule exists
	function exist_rule($id){
		$id=(int)$id;
		$row = $this->DB->GetRow("SELECT * FROM `".DB_PREFIX."rules` WHERE `id`='$id'");
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
		if ($rule_array['type']=='' || $rule_array['rule']=='' || $rule_array['proto']==''){
			return "add rule failed";
		}
		/*
		elseif (!$this->check_rule($rule_array['rulename'])){
			return $GLOBALS['admin'][46].'<br />'.$GLOBALS['admin'][43];
		}
		elseif (!$this->check_password($rule_array['passwd'])){
			return $GLOBALS['admin'][46].'<br />'.$GLOBALS['admin'][73];
		}
		elseif (!$this->check_email($rule_array['email'])){
			return $GLOBALS['admin'][46].'<br />'.$GLOBALS['admin'][45];
		}
		*/
		
		$this->DB->Execute("INSERT INTO `".DB_PREFIX."rules` (`type`, `rule`, `proto`) VALUES ('".$rule_array['type']."', '".$rule_array['rule']."', '".$rule_array['proto'].")");
		
		return $GLOBALS['admin'][47];
	}
	
	//Change rule
	function change_rule($id, $rule){
		$id=(int)$id;
		if ($this->exist_rule($id)){
			$this->DB->Execute("UPDATE `".DB_PREFIX."rules` SET `rule`='".$rule."' WHERE `id`='$id'");
			return 'Rule updated!';
		}
		return 'Rule Not updated! Call Administrator...';
	}
	
	
	
	//Delete a rule
	function del_rule($id){
		$id=(int)$id;
		if ($this->exist_rule($id)){
			$this->DB->Execute("DELETE FROM `".DB_PREFIX."rules` WHERE `id`='$id'");
			//$this->DB->Execute("DELETE FROM `".DB_PREFIX."ip_history` WHERE `rule_id`='$id'");
			//$this->DB->Execute("DELETE FROM `".DB_PREFIX."sessions` WHERE `rule_id`='$id'");
			//$this->DB->Execute("DELETE FROM `".DB_PREFIX."rule_blocks` WHERE `rule_id`='$id'");
			return 'Deleted';
		}
		else{
			return 'User doesn\'t exist (del_rule)';
		}
	}
	
	
	//Get rule info
	function get_rule($id){
		$id=(int)$id;
		if ($this->exist_rule($id)){
			return $this->DB->GetRow("SELECT * FROM `".DB_PREFIX."rules` WHERE id='$id'");
		}
		exit('User doesn\'t exist (get_rule)');
	}
	

	//Get id of all rules
	function get_rules_id(){
		$rules=array();
		$rs = & $this->DB->Execute("SELECT `id` FROM `".DB_PREFIX."rules`");
		while (!$rs->EOF){
			$rules[]=$rs->fields;
			$rs->MoveNext();
		}
		return $rules;
	}
	
	//Get option list
	function option_list($id){
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
}
?>