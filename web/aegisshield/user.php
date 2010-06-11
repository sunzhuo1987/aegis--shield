<?php
require_once('includes/config.php');

//防止恶意或未登录用户直接从浏览器调用操作页面
if($_status != AUTH_LOGGED || !($_user_active['privilege']==USER)){
	header("Refresh: 0;URL=index.php");
	exit();
}

//Load dictionary
//$language_file='lang/'.$_user_active['language'].'/dictionary.php';
$language_file='lang/en/dictionary.php';
if (file_exists($language_file)){
	require_once($language_file);
}
else{
	exit('NO Dictionary!');
}

// 输出网页文件的头部
echo $PAGE->getHeader('user',$admin[40]);
?>

<div id="container">
	<table id="header"><tr>
	<td class="left"><?php echo $UTILITY->get_logo('admin'); ?></td>
	<td class="right"><h3><?php echo $admin[1].' '.$_user_active['name'].' '.$_user_active['surname']; ?></h3><?php echo $admin[2]; ?>: <?php echo $admin[116]; ?><br />
    <?php echo $admin[3]; ?>: <?php echo $SESSION->last_log(); ?></td>
	</tr></table>

	<table id="central"><tr>
		<td id="menu">
		<a href="user.php"><?php echo '首页'/*$admin[4]*/; ?></a><br />
		<br />
		<a href="?action=change_password"><?php echo '修改密码'/*$admin[6]*/; ?></a><br />
		<br />
		<a href="?action=view_logs"><?php echo 'view logs'?></a>
		<br />
		<a href="?action=manage_rules"><?php echo 'rules management'; ?></a><br />
		<br />
		<a href="?action=logout"><?php echo $admin[10];?></a>
		</td>
		<td id="navigation">
		<?php
			switch($_GET['action']){
				case 'manage_user':
					include('interfaces/admin/manage_user.php');
				break;
				case 'view_logs':
					include('interfaces/common/view_logs.php');
				break;
				case 'manage_rules':
					include('interfaces/common/manage_rules.php');
				break;
				default:
					echo '<h4>'.$admin[155].'</h4>';
					$n_users=$DB->GetRow("SELECT COUNT(*) FROM `".DB_PREFIX."users`");
					$n_blocks=$DB->GetRow("SELECT COUNT(*) FROM `".DB_PREFIX."block_settings`");
					$n_groups=$DB->GetRow("SELECT COUNT(*) FROM `".DB_PREFIX."groups`");
					$n_plugins=$DB->GetRow("SELECT COUNT(*) FROM `".DB_PREFIX."plugins`");
					$n_iptables=$DB->GetRow("SELECT COUNT(*) FROM `".DB_PREFIX."iptables_variables`");
					echo '<div id="general_info">';
					echo $admin[156].': '.$n_users[0].'<br />';
					echo $admin[157].': '.$n_groups[0].'<br />';
					echo $admin[158].': '.$n_blocks[0].'<br />';
					echo $admin[159].': '.$n_plugins[0].'<br />';
					echo $admin[160].': '.$n_iptables[0].'<br />';
					echo $admin[150].': '.$SYSTEM_INFO->GetUptime().'<br />';
					echo '</div>';
			}
		?>
		</td>
	</tr></table>

	<div id="footer"><?php echo $PAGE->get_credits(); ?></div>
</div>

<?php
echo $PAGE->getFooter();
?>
