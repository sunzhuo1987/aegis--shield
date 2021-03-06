<?php
//Include files
require_once('includes/connection_settings.php');
require_once('includes/session_settings.php');
require_once('includes/jpgraph_settings.php');

//Class files
require_once('classes/adodb/adodb.inc.php');
require_once('classes/session_class.php');
require_once('classes/page_class.php');
require_once('classes/utility_class.php');
//require_once('classes/group_class.php');
require_once('classes/user_class.php');
require_once('classes/rule_class.php');
require_once('classes/language_class.php');
//require_once('classes/setting_class.php');
require_once('classes/alerts_class.php');
require_once('classes/system_info_class.php');
require_once('classes/graph_data_class.php');
require_once('classes/approto_class.php');

//Do not change
define('AUTH_NOT_LOGGED', 0);
define('AUTH_FAILED', 1);
define('AUTH_LOGGED', 2);
define('ACTIVE',1);
define('NOACTIVE',0);
define('ADMIN',2);
define('USER',1);
define('GUEST',0);
define('GUEST_BLOCK',-1);
define('USER_GUEST',-1);
define('EXTERNAL_STMP',1);
define('LOCAL_STMP',0);
define('SMTP_AUTH_YES',true);
define('SMTP_AUTH_NO',false);

//Advanced features
define('DB_PREFIX',"ag_");
define('OPTIMIZE_DAY',10);

//Create object
$DB = NewADOConnection($_type_of_db_server);
$_res_db = @$DB->Connect($_host, $_user, $_password, $_db_name);
if (!$_res_db){
	exit('Database problem! Check your configuration');
}
$SESSION = new ag_session($_session_time, $_session_gc_time, &$DB);
$PAGE = new page();
$UTILITY = new utility();
$USER = new user(&$DB);
$RULE = new rule(&$DB);
$LANGUAGE = new language();
$ALERTS = new alerts(&$DB);
$GRAPH_DATA = new graph_data(&$DB);
$APPROTO = new approto(&$DB);
$SYSTEM_INFO = new system_info();



//Error reporting
error_reporting(E_ALL ^ E_NOTICE);

//Logout
if ($_GET['action']=='logout'){
	$SESSION->logout();
}

//Check if session is active
list($_status, $_user_active) = $SESSION->auth_get_status();

?>