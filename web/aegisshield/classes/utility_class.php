<?php
//Utility class
class utility{

	//Constructor
	function utility(){}
	
	//HEX to RGB
	function hex2rgb($hex) {
		$color = str_replace('#','',$hex);
		$rgb = array(hexdec(substr($color,0,2)),
		hexdec(substr($color,2,2)),
		hexdec(substr($color,4,2)));
		return $rgb;
	}
	
	//RBG to HEX
	function rgb2hex($r,$g,$b){}
	
	//Get DB image
	function getImageDb($dbms_selected){
		switch ($dbms_selected) {
			case "mysql":
				$buffer="<a href=\"http://www.mysql.com\" target=\"_blank\"><img src=\"images/mysql.gif\" alt=\"\" title=\"\"></a>";
			break;
			case "postgres":
				$buffer="<a href=\"http://www.postgresql.org\" target=\"_blank\"><img src=\"images/postgresql.gif\" alt=\"\" title=\"\"></a>";
			break;
			case "sqlite":
				$buffer="<a href=\"http://www.sqlite.org\" target=\"_blank\"><img src=\"images/sqlite.gif\" alt=\"\" title=\"\"></a>";
			break;
			case "oci8":
				$buffer="<a href=\"http://www.oracle.com\" target=\"_blank\"><img src=\"images/oracle.gif\" alt=\"\" title=\"\"></a>";
			break;
		}
		return $buffer;
	}

	//Get logo image
	function get_logo($link){
		return "<a href=\"$link\"><img src=\"images/logo.JPG\" alt=\"\" title=\"\" /></a>";
	}
}
?>