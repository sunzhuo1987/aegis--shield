<?php
require_once('includes/config.php');

//防止恶意或未登录用户直接从浏览器调用操作页面
if($_status != AUTH_LOGGED || $_user_active['privilege']!=USER){
	header("Refresh: 0;URL=index.php");
	exit();
}

//Load dictionary
$language_file='lang/en/dictionary.php';
if (file_exists($language_file)){
	require_once($language_file);
}
else{
	exit('NO Dictionary!');
}

echo $PAGE->getHeader('user',"User interface");
?>

<div id="container">
	<table id="header"><tr>
	<td class="left"><?php echo $UTILITY->get_logo('admin'); ?></td>
	<td class="right"><h3><?php echo $admin[1].' '.$_user_active['name'].' '.$_user_active['surname']; ?>
	</h3><?php echo $admin[2]; ?>: <?php echo "User"; ?><br />
    <?php echo $admin[3]; ?>: <?php echo $SESSION->last_log(); ?></td>
	</tr></table>

	<table id="central"><tr>
		<td id="menu">
		<a href="user.php"><?php echo $admin[4]; ?></a><br />
		<br />

		<a href="?action=view_logs"><?php echo 'view logs'?></a><br />
		<a href="?action=view_proto"><?php echo 'view proto'?></a><br />
		<br />

		<a href="?action=manage_rules"><?php echo 'rules management'; ?></a><br />
		<br />
		<a href="?action=logout"><?php echo $admin[10];?></a>
		</td>
		<td id="navigation">
		<?php
			switch($_GET['action']){
				case 'view_logs':
					include('interfaces/common/view_logs.php');
				break;
				
				case 'view_proto':
					include('interfaces/common/view_proto.php');	
				break;
				break;
				case 'manage_rules':
					include('interfaces/user/manage_rules.php');
				break;
				default:
					include('interfaces/common/general_info.php');
			}
		?>
		</td>
	</tr></table>

	<div id="footer"><?php echo $PAGE->get_credits(); ?></div>
</div>

<?php
echo $PAGE->getFooter();
?>