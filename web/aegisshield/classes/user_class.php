<?php
//User class
class user {

	var $DB;

	//Constructor
	function user($DB){
		$this->DB = $DB;
	}
	
	//Check if a user exists
	function exist_user($id){
		$id=(int)$id;
		$row = $this->DB->GetRow("SELECT * FROM `".DB_PREFIX."users` WHERE `id`='$id'");
		$tot=count($row);
		if ($tot>0){
			return true;
		}
		else{
			return false;
		}
	}
	
	//Check if a mail exists
	function exist_email($email){
		$row = $this->DB->GetRow("SELECT * FROM `".DB_PREFIX."users` WHERE `email`='$email'");
		$tot=count($row);
		if ($tot>0){
			return true;
		}
		else{
			return false;
		}
	}
	
	//Check user validity
	function check_user($user){
		if (strlen($user)>=5){
			return true;
		}
		else{
			return false;
		}
	}
	
	//Check length password
	function check_password($password){
		if (strlen($password)>=5){
			return true;
		}
		else{
			return false;
		}
	}
	
	//Check email validity
	function check_email($email){
		if (ereg("^.+@[^\.].*\.[a-z]{2,}$", $email)){
			return true;
		}
		else{
			return false;
		}
	}
	
	//Email to id
	function email_to_id($email){
		if ($this->check_email($email)){
			$row = $this->DB->GetRow("SELECT `id` FROM `".DB_PREFIX."users` WHERE `email`='$email'");
			$tot=count($row);
			if ($tot>0){
				return $row['id'];
			}
		}
		return '-1';
	}
	
	//User to id
	function id_to_user($id){
		$id=(int)$id;
		if ($this->exist_user($id)){
			$row = $this->DB->GetRow("SELECT `username` FROM `".DB_PREFIX."users` WHERE `id`='$id'");
			return $row['username'];
		}
		exit('User doesn\'t exist (id_to_user)');
	}
	
	//Id to user
	function user_to_id($user){
		$row = $this->DB->GetRow("SELECT * FROM `".DB_PREFIX."users` WHERE `username`='$user'");
		return $row['id'];
	}
	
	//Add a new user
	function add_user($user_array){
		if ($user_array['name']=='' || $user_array['surname']=='' || $user_array['privilege']==''){
			return $GLOBALS['admin'][46].'<br />'.$GLOBALS['admin'][44];
		}
		elseif (!$this->check_user($user_array['username'])){
			return $GLOBALS['admin'][46].'<br />'.$GLOBALS['admin'][43];
		}
		elseif (!$this->check_password($user_array['passwd'])){
			return $GLOBALS['admin'][46].'<br />'.$GLOBALS['admin'][73];
		}
		elseif (!$this->check_email($user_array['email'])){
			return $GLOBALS['admin'][46].'<br />'.$GLOBALS['admin'][45];
		}
		
		$sql = "INSERT INTO `".DB_PREFIX."users` (`username`, `passwd`, `privilege`, `name`, `surname`, `email`, `created`) VALUES ('".$user_array['username']."', '".md5($user_array['passwd'])."', '".$user_array['privilege']."', '".$user_array['name']."', '".$user_array['surname']."', '".$user_array['email']."', NOW())";
		$this->DB->Execute($sql);
		
		return $GLOBALS['admin'][329];
	}
	
	//Change user password
	function change_password($id, $password){
		$id=(int)$id;
		if ($this->exist_user($id) && $this->check_password($password)){
			$this->DB->Execute("UPDATE `".DB_PREFIX."users` SET `passwd`='".md5($password)."' WHERE `id`='$id'");
			return $GLOBALS['admin'][70];
		}
		return $GLOBALS['admin'][352];
	}
	
	//Send email with the new password
	/*
	function reset_password($email){
		$id=$this->email_to_id($email);
		if ($id>=0){
		
			//Random password
			$char_list = "abcdefghiljkmnopqrstuvwxyz0123456789";
			srand((double)microtime()*1000000);
			$elaborazione = '' ;
			for ($counter=0; $counter<8; $counter++) {
				$random = rand() % 35;
				$char = substr($char_list, $random, 1);
				$work = $work . $char;
			}
	
			$res=$this->DB->Execute("UPDATE `".DB_PREFIX."users` SET `passwd`='".md5($work)."' WHERE `email`='$email'");
			$row_user=$this->get_user($id);
			
			$SETTING_TMP = new setting(&$this->DB);
			$value_email=$SETTING_TMP->get_value('email');
			$value_url=$SETTING_TMP->get_value('url');
			unset($SETTING_TMP);
			
			$MAIL_TMP = new mailer(serialize(array('url'=>$value_url)));
			$text=$GLOBALS['admin'][87]."\n\n".$GLOBALS['admin'][21].': '.$row_user['username']."\n".$GLOBALS['admin'][22].': '.$work;
			$MAIL_TMP->send_mail($value_email, $value_email, $row_user['email'], $row_user['email'], $GLOBALS['admin'][85], $text );
			unset($MAIL_TMP);

			return $GLOBALS['admin'][84];
		}
		return $GLOBALS['admin'][86];
	}
	*/
	
	//Delete a user
	function del_user($id){
		$id=(int)$id;
		if ($this->exist_user($id)){
			$this->DB->Execute("DELETE FROM `".DB_PREFIX."users` WHERE `id`='$id'");
			$this->DB->Execute("DELETE FROM `".DB_PREFIX."ip_history` WHERE `user_id`='$id'");
			$this->DB->Execute("DELETE FROM `".DB_PREFIX."sessions` WHERE `user_id`='$id'");
			return $BLOBALS['admin'][344];
		}
		else{
			return 'User doesn\'t exist (del_user)';
		}
	}
	
	//Change user settings
	function set_user($user_array){
		if ($this->exist_user($user_array['id'])){
			if (!$this->check_email($user_array['email'])){
				return $GLOBALS['admin'][75].'<br />'.$GLOBALS['admin'][45];
			}
			
			if($user_array['group_id']=='' || $user_array['account']=='' || $user_array['language']=='' || $user_array['privilege']==''){
				return $GLOBALS['admin'][75].'<br />'.$GLOBALS['admin'][44];
			}
			
			$user_before=$this->get_user($user_array['id']);
			if ($user_array['group_id']!=$user_before['group_id']){
				$this->DB->Execute("DELETE FROM `".DB_PREFIX."user_blocks` WHERE `user_id`='".$user_array['id']."'");			
			}
			
			$this->DB->Execute("UPDATE `".DB_PREFIX."users` SET `privilege`='".$user_array['privilege']."', `phone`='".$user_array['phone']."', `fax`='".$user_array['fax']."', `mobile_phone`='".$user_array['mobile_phone']."', `email`='".$user_array['email']."', `language`='".$user_array['language']."', `city`='".$user_array['city']."', `nation`='".$user_array['nation']."', `place`='".$user_array['place']."', `zip_code`='".$user_array['zip_code']."', `address`='".$user_array['address']."', `group_id`='".$user_array['group_id']."', `account`='".$user_array['account']."' WHERE `id`='".$user_array['id']."'");
			
			return $GLOBALS['admin'][59];
		}
		return 'Error: the user with the id '.$user_array['id'].' doesn\'t exist';
	}
	
	//Get user info
	function get_user($id){
		$id=(int)$id;
		if ($this->exist_user($id)){
			return $this->DB->GetRow("SELECT * FROM `".DB_PREFIX."users` WHERE id='$id'");
		}
		exit('User doesn\'t exist (get_user)');
	}
	
	//Get last user registered
	function last_user(){
		$row=$this->DB->GetRow("SELECT * FROM `".DB_PREFIX."users` ORDER BY rtime DESC LIMIT 0,1");
		return $row;
	}
	
	//Privilege list
	function privilege_list($privilege=false){
		$buffer='<select name="privilege">';
		$array_privilege=$this->get_privilege_array();
		foreach ($array_privilege as $key => $value){
			$buffer.='<option ';
			if ($privilege==$value){
				$buffer.='selected="selected" ';
			}
			$buffer.='value="'.$value.'">'.$this->get_privilege_name($value).'</option>';
		}
		$buffer.='</select>';
		return $buffer;
	}
	
	//Get privilege array
	function get_privilege_array(){
		return array(ADMIN, USER);
	}

	//Get privilege name
	function get_privilege_name($id){
		$id=(int)$id;
		switch($id){
			case ADMIN:
				$buffer=$GLOBALS['admin'][116];
			break;
			case USER:
				$buffer=$GLOBALS['admin'][117];
			break;
			case GUEST:
				$buffer=$GLOBALS['admin'][118];
			break;			
		}
		return $buffer;
	}

	//Get id of all users
	function get_users_id(){
		$users=array();
		$rs = & $this->DB->Execute("SELECT `id` FROM `".DB_PREFIX."users`");
		while (!$rs->EOF){
			$users[]=$rs->fields;
			$rs->MoveNext();
		}
		return $users;
	}

	//Get account img
	function get_account_img($id){
		$id=(int)$id;
		switch ($id){
			case ACTIVE:
				$buffer='<img src="images/active.gif" alt="'.$GLOBALS['admin'][61].'" title="'.$GLOBALS['admin'][61].'" />';
			break;
			case NOACTIVE:
				$buffer='<img src="images/inactive.gif" alt="'.$GLOBALS['admin'][62].'" title="'.$GLOBALS['admin'][62].'" />';
			break;		
		}
		return $buffer;
	}
	
	//Get state log img
	function get_log_img($id){
		$id=(int)$id;
		switch ($id){
			case AUTH_LOGGED:
				$buffer='<img src="images/active.gif" alt="'.$GLOBALS['admin'][112].'" title="'.$GLOBALS['admin'][112].'" />';
			break;
			case AUTH_FAILED:
				$buffer='<img src="images/inactive.gif" alt="'.$GLOBALS['admin'][113].'" title="'.$GLOBALS['admin'][113].'" />';
			break;		
		}
		return $buffer;
	}
	
	//Get option list
	function option_list($id){
		$id=(int)$id;
		if ($this->exist_user($id)){
			$buffer='<a href="admin.php?action=manage_user&amp;type=configure&amp;id='.$id.'"><img src="images/configure.png" alt="'.$GLOBALS['admin'][63].'" title="'.$GLOBALS['admin'][63].'" /></a> <a href="admin.php?action=manage_user&amp;type=delete&amp;id='.$id.'"><img src="images/delete.png" alt="'.$GLOBALS['admin'][64].'" title="'.$GLOBALS['admin'][64].'" /></a> <a href="admin.php?action=manage_user&amp;type=change_password&amp;id='.$id.'"><img src="images/change_password.png" alt="'.$GLOBALS['admin'][65].'" title="'.$GLOBALS['admin'][65].'" /></a> <a href="admin.php?action=manage_user&amp;type=view&amp;id='.$id.'"><img src="images/information.png" alt="'.$GLOBALS['admin'][66].'" title="'.$GLOBALS['admin'][66].'" /></a> <a href="admin.php?action=manage_user&amp;type=log&amp;id='.$id.'"><img src="images/logs.png" alt="'.$GLOBALS['admin'][67].'" title="'.$GLOBALS['admin'][67].'" /></a>';
			return $buffer;
		}
		return 'User doesn\'t exist (option_list)';
	}
	
	//Get account list
	function account_list($state=false){
		$account=$this->get_account_array();
		$buffer='<select name="account">';
		
		foreach ($account as $key => $value){
			if ($state==$value['id']){
				$buffer.='<option selected="selected" value="'.$value['id'].'">'.$value['name'].'</option>';
			}
			else{
				$buffer.='<option value="'.$value['id'].'">'.$value['name'].'</option>';
			}
		}
		$buffer.='</select>';
		return $buffer;
	}
	
	//Get account
	function get_account($id){
		$account=$this->get_account_array();
		foreach ($account as $value){
			if ($value['id']==$id){
				return $value['name'];
			}
		}
		return 'error';
	}
	
	//Get account array
	function get_account_array(){
		return array(array('id'=>ACTIVE, 'name'=>$GLOBALS['admin'][61]), array('id'=>NOACTIVE, 'name'=>$GLOBALS['admin'][62]));
	}
	
	//Get log list
	function get_log_list($id){
		$id=(int)$id;
		if ($this->exist_user($id)){
			$buffer='';
			$buffer.='<tr><th>'.$GLOBALS['admin'][380].'</th><th>'.$GLOBALS['admin'][381].'</th><th>'.$GLOBALS['admin'][382].'</th></tr>';
			
			$rs=$this->DB->Execute("SELECT * FROM `".DB_PREFIX."ip_history` WHERE `user_id`='$id' ORDER BY `date` DESC");
			$log_array=array();
			while (!$rs->EOF) {
				$log_array=$rs->fields;
				$buffer.='<tr><td>'.$log_array['date'].'</td><td class="center">'.$this->get_log_img($log_array['state']).'</td><td>'.$log_array['ip'].'</td></tr>';
				$rs->MoveNext();
			}
			return $buffer;
		}
		return 'User doesn\'t exist (get_log_list)';
	}

	//Get interface links
	function link_interface($privilege, $interface){
		$buffer='';
		switch($interface){
			case ADMIN:
				$buffer='<a href="user.php">'.$GLOBALS['admin'][40].'</a><br />';
			break;
			case USER:
				if ($privilege==ADMIN){
					$buffer='<a href="admin.php">'.$GLOBALS['admin'][39].'</a> | ';
				}
				else{
					$buffer='';
				}
			break;
			default:
				$buffer='';
		}
		return $buffer;
	}

}
?>