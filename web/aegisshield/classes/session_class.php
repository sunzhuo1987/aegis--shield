<?php
//会话管理类
class ag_session{

	var $ag_session_id; //SessionId
	var $session_time; //Session time live
	var $session_gc_time; //Garbage collection time
	var $DB;

	//Constructor
	function ag_session($session_time, $session_gc_time, &$DB) {
		$this->ag_session_id = (!isset($_COOKIE['ag_session_id'])) ? md5(uniqid(microtime())) : $_COOKIE['ag_session_id'];
		$this->session_time = $session_time;
		$this->session_gc_time = $session_gc_time;
		$this->DB = $DB;
	}
	
	//If possible autologin into system
	function auth_get_status(){
		$this->session_gc();
		if (isset($_COOKIE['ag_session_id'])){
			$user_id=$this->user_id();
			$row=$this->DB->GetRow("SELECT * FROM `".DB_PREFIX."users` WHERE `id`='".$user_id."'");
			//var_dump($row);
			if (count($row)<1){
				return array(AUTH_NOT_LOGGED, NULL);
			}
			else{
				$this->DB->Execute("UPDATE `".DB_PREFIX."sessions` SET `date`=NOW() WHERE `id` = '{$this->ag_session_id}'");
				return array(AUTH_LOGGED,$row);
			}
		}
		else{
			return array(AUTH_NOT_LOGGED, NULL);
		}
	}

	//登录
	function login($username, $passwd){
		$row=$this->DB->GetRow("SELECT * FROM `".DB_PREFIX."users` WHERE `username`='".$username."' AND `passwd`='".md5($passwd)."' AND `account`=".ACTIVE."");
		if (count($row)<1){
			$row_failed=$this->DB->GetRow("SELECT `id` FROM `".DB_PREFIX."users` WHERE `username`='".$username."'");
			if (count($row_failed)>=1){
				//写入日志
				$this->set_log($row_failed['id'], AUTH_FAILED);
			}
			return array(AUTH_FAILED, NULL);
		}
		else{
			$cookie_expire = ($this->session_time > 0) ? (time() + $this->session_time) : 0;
			setcookie('ag_session_id', $this->ag_session_id, $cookie_expire);
			$this->DB->Execute("INSERT INTO `".DB_PREFIX."sessions` (`id`, `user_id`, `vars`, `date`) VALUES ('".$this->ag_session_id."', '".$row['id']."', '', NOW())");
			//Write log
			$this->set_log($row['id'], AUTH_LOGGED);		
			return array(AUTH_LOGGED, $row);
		}
	}

	//日志记录
	function set_log($user_id, $type_auth){
		$this->DB->Execute("INSERT INTO `".DB_PREFIX."ip_history` (`user_id`, `ip` , `date`, `state`) VALUES('".$user_id."', '".$_SERVER["REMOTE_ADDR"]."', NOW(), '".$type_auth."')");
		
		$row=$this->DB->GetRow("SELECT COUNT(*) FROM `".DB_PREFIX."ip_history` WHERE `user_id`='$user_id'");
		$n_rows=$row[0]-N_LOG;
		if ($n_rows>0){
			$this->DB->Execute("DELETE FROM `".DB_PREFIX."ip_history` WHERE `user_id`='$user_id' ORDER BY date ASC LIMIT ".$n_rows."");
		}
	}

	//注销
	function logout(){
		if (isset($_COOKIE['ag_session_id'])){
			$this->DB->Execute("DELETE FROM `".DB_PREFIX."sessions` WHERE `id`='{$this->ag_session_id}'");
			setcookie('ag_session_id', '', time() - 3600);
			return true;
		}
		return false;
	}

	//Record a var in a session
	function register_var($name, $value=false) {
		$_MY_SESSION = array();
		$result = $this->DB->GetRow("SELECT `vars` FROM `".DB_PREFIX."sessions` WHERE `id` = '{$this->ag_session_id}'");
		if (count($session_query) >= 1){
			$_MY_SESSION = unserialize($result['vars']);

			if ($value==false){
				$serialize_TMP='';
			}
			else{
				$_MY_SESSION[$name] = $value;
				$serialize_TMP=serialize($_MY_SESSION);
			}	
	
			$this->DB->Execute("UPDATE `".DB_PREFIX."sessions` SET `vars` = '" . $serialize_TMP . "' WHERE `sessid` = '{$this->ag_session_id}'");
		}
		else{
			if ($value==false){
			}
			else{
				$_MY_SESSION[$name] = $value;
				$query="UPDATE `".DB_PREFIX."sessions` SET `vars` = '".serialize($_MY_SESSION)."' WHERE `id` = '{$this->ag_session_id}'";
				$this->DB->Execute($query);
			}
		}
	}

	//Read all vars or a single var if $key is set
	function read_var($key = ''){
		$row = $this->DB->GetRow("SELECT `vars` FROM `".DB_PREFIX."sessions` WHERE `id` = '{$this->ag_session_id}'");
		if (count($row) > 0){			
			$session_vars = unserialize($row['vars']);
			return (isset($key)) ? $session_vars[$key] : $session_vars;
		}
	}

	//Destroy all vars
	function destroy_var() {
		$this->DB->Execute("UPDATE `".DB_PREFIX."sessions` SET `vars` = '' WHERE `id` = '{$this->ag_session_id}'");
	}

	//Garbage collection
	function session_gc() {
		$this->DB->Execute("DELETE FROM `".DB_PREFIX."sessions` WHERE `date` < " . (time() - $this->session_gc_time));
	}

	//Get info about last log of user logged
	function get_last_log(){
		$user_id=$this->user_id();
		$row=$this->DB->GetRow("SELECT * FROM `".DB_PREFIX."ip_history` WHERE `user_id`='".$user_id."' AND `state`='".AUTH_LOGGED."' ORDER BY date DESC LIMIT 1");
		return $row;
	}

	//Get user id
	function user_id(){
		if (isset($_COOKIE['ag_session_id'])){
			$row=$this->DB->GetRow("SELECT `user_id` FROM `".DB_PREFIX."sessions` WHERE `id`='{$this->ag_session_id}'");
			$row_tot=count($row);
			if ($row_tot>0){
				return $row['user_id'];
			}
		}
		return '-1';
	}
	
	//Get last user log
	function last_log(){
		if (isset($_COOKIE['ag_session_id'])){
			$user_id=$this->user_id();
			$row=$this->DB->GetRow("SELECT `date` FROM `".DB_PREFIX."ip_history` WHERE `user_id`='$user_id' ORDER BY `date` desc LIMIT 0,1");
			return $row['date'];
		}
	}

}
?>