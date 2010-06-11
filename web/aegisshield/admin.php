<?php
require_once('includes/config.php');

if($_status != AUTH_LOGGED || $_user_active['privilege']!=ADMIN){
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

echo $PAGE->getHeader('admin',$admin[39]);
?>

<div id="container">
	<table id="header"><tr>
	<td class="left"><?php echo $UTILITY->get_logo('admin'); ?></td>
	<td class="right"><h3><?php echo $admin[1].' '.$_user_active['name'].' '.$_user_active['surname']; ?></h3><?php echo $admin[2]; ?>: <?php echo $admin[116]; ?><br />
    <?php echo $admin[3]; ?>: <?php echo $SESSION->last_log(); ?></td>
	</tr></table>

	<table id="central"><tr>
		<td id="menu">
		<a href="admin.php"><?php echo $admin[4]; ?></a><br />
		<br />
		<a href="?action=add_user"><?php echo $admin[5]; ?></a><br />
		<a href="?action=manage_user"><?php echo $admin[6]; ?></a><br />
		<br />
		<a href="?action=view_logs"><?php echo 'view logs'?></a><br />
		<br />
		<a href="?action=manage_var"><?php echo $admin[7]; ?></a><br />
		<a href="?action=manage_rules"><?php echo 'rules management'; ?></a><br />
		<br />
		<a href="?action=info_system"><?php echo $admin[9]; ?></a><br />
		<br />
		<a href="?action=logout"><?php echo $admin[10];?></a>
		</td>
		<td id="navigation">
		<?php
			switch($_GET['action']){
				case 'add_user':
					include('interfaces/admin/add_user.php');
				break;
				case 'manage_user':
					include('interfaces/admin/manage_user.php');
				break;
				case 'view_logs':
					include('interfaces/common/view_logs.php');
				break;
				case 'manage_var':
					include('interfaces/admin/manage_var.php');
				break;
				case 'manage_rules':
					include('interfaces/common/manage_rules.php');
				break;
				case 'info_system':
					include('interfaces/admin/info_system.php');
				break;
				default:
					/*
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
					*/
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