<?php
//Class to make pages
class page{

	//Constructor
	function page(){}
	
	//Header
	function getHeader($interface, $title){
		$buffer='<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta name="description" content="Aegisshield - Network traffic analysis and detection!" />
<meta name="author" content="[aegisshield]" />
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<meta name="author" content="[aegisshield]" />
<meta name="copyright" content="Copyright (c) 2009-2010	aegisshield" />
<meta name="generator" content="aegisshield - http://code.google.com/p/aegis--shield/" />
<link href="style/default.css" rel="stylesheet" type="text/css" />';

if (file_exists('style/'.$interface.'.css')){
	$buffer.="\n".'<link href="style/'.$interface.'.css" rel="stylesheet" type="text/css" />';
}

$buffer.='<title>'.$title.'</title>
<!--
******************************************************************
***** Aegisshield - http://code.google.com/p/aegis--shield/ ******
******************************************************************
-->
</head>
<body>';
		return $buffer;
	}
	
	//Footer
	function getFooter(){
		$buffer='</body></html>';
		return $buffer;
	}
	
	//Get credits
	function get_credits(){
		return '<br /><br />The contents of this webpage are copyright &copy;2009-'.date('Y').' aegisshield. All Rights Reserved.<br/>';
	}
}
?>